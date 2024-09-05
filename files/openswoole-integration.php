<?php
declare(strict_types=1);

use DDTrace\HookData;
use DDTrace\Integrations\Swoole\SwooleIntegration;
use DDTrace\SpanStack;
use DDTrace\Tag;
use DDTrace\Type;
use DDTrace\Util\Normalizer;
use OpenSwoole\Http\Request;

use Swoole\Http\Server;
use function DDTrace\Config\integration_analytics_enabled;
use function DDTrace\Config\integration_analytics_sample_rate;
use function DDTrace\consume_distributed_tracing_headers;
use function DDTrace\extract_ip_from_headers;
use function DDTrace\find_active_exception;
use function DDTrace\hook_method;
use function DDTrace\install_hook;
use function DDTrace\Internal\handle_fork;
use function DDTrace\root_span;

if (\extension_loaded('ddtrace') === false) {
    exit;
}

hook_method(
    'OpenSwoole\Http\Server',
    '__construct',
    null,
    function ($server) {
        $server->on('workerstart', function () {
        });
    }
);

hook_method(
    'OpenSwoole\Http\Server',
    'on',
    null,
    function ($server, $scope, $args, $retval) {
        if ($retval === false) {
            return; // Callback wasn't set
        }

        list($eventName, $callback) = $args;

        $eventName = strtolower($eventName);
        switch ($eventName) {
            case 'request':
                instrumentRequestStart($callback);
                break;
            case 'workerstart':
                instrumentWorkerStart($callback);
                break;
        }
    }
);

function instrumentWorkerStart(callable $callback)
{
    install_hook(
        $callback,
        function (HookData $hook) {
            handle_fork();
        }
    );
}

hook_method(
    'OpenSwoole\Http\Response',
    'end',
    function ($response, $scope, $args) {
        $rootSpan = root_span();
        if ($rootSpan === null) {
            return;
        }

        if (!$rootSpan->exception
            && ((int)$rootSpan->meta[Tag::HTTP_STATUS_CODE]) >= 500
            && $ex = find_active_exception()
        ) {
            $rootSpan->exception = $ex;
        }
    }
);

hook_method(
    'OpenSwoole\Http\Response',
    'header',
    function ($response, $scope, $args) {
        $rootSpan = root_span();
        if ($rootSpan === null || \count($args) < 2) {
            return;
        }

        /** @var string[] $args */
        list($key, $value) = $args;

        $allowedHeaders = \dd_trace_env_config("DD_TRACE_HEADER_TAGS");
        $normalizedHeader = preg_replace("([^a-z0-9-])", "_", strtolower($key));
        if (\array_key_exists($normalizedHeader, $allowedHeaders)) {
            $rootSpan->meta["http.response.headers.$normalizedHeader"] = $value;
        }
    }
);

hook_method(
    'OpenSwoole\Http\Response',
    'status',
    function ($response, $scope, $args) {
        $rootSpan = root_span();
        if ($rootSpan && \count($args) > 0) {
            $rootSpan->meta[Tag::HTTP_STATUS_CODE] = $args[0];
        }
    }
);

function instrumentRequestStart(callable $callback)
{
    install_hook(
        $callback,
        function (HookData $hook) {
            $rootSpan = $hook->span(new SpanStack());
            $rootSpan->name = "web.request";
            $rootSpan->service = \ddtrace_config_app_name('openswoole');
            $rootSpan->type = Type::WEB_SERVLET;
            $rootSpan->meta[Tag::COMPONENT] = 'openswoole';
            $rootSpan->meta[Tag::SPAN_KIND] = Tag::SPAN_KIND_VALUE_SERVER;
            $name = $this->getName();
            if (integration_analytics_enabled($name)
                || (!$this->requiresExplicitTraceAnalyticsEnabling() && \dd_trace_env_config("DD_TRACE_ANALYTICS_ENABLED"))) {
                $rootSpan->metrics[Tag::ANALYTICS_KEY] = integration_analytics_sample_rate($name);
            }

            $args = $hook->args;
            /** @var Request $request */
            $request = $args[0];

            $headers = [];
            $allowedHeaders = \dd_trace_env_config('DD_TRACE_HEADER_TAGS');
            foreach ($request->header as $name => $value) {
                $headers[strtolower($name)] = $value;
                $normalizedHeader = preg_replace("([^a-z0-9-])", "_", strtolower($name));
                if (\array_key_exists($normalizedHeader, $allowedHeaders)) {
                    $rootSpan->meta["http.request.headers.$normalizedHeader"] = $value;
                }
            }
            consume_distributed_tracing_headers(function ($key) use ($headers) {
                return $headers[$key] ?? null;
            });

            if (\dd_trace_env_config("DD_TRACE_CLIENT_IP_ENABLED")) {
                $res = extract_ip_from_headers($headers + ['REMOTE_ADDR' => $request->server['remote_addr']]);
                $rootSpan->meta += $res;
            }

            if (isset($headers["user-agent"])) {
                $rootSpan->meta["http.useragent"] = $headers["user-agent"];
            }

            $rawContent = $request->rawContent();
            if ($rawContent) {
                // The raw content will always be populated if the request is a POST request, independent of the
                // Content-Type header.
                // However, it may not be json-decodable
                $postFields = json_decode($rawContent, true);
                if (is_null($postFields)) {
                    // Fallback to the post fields, which is an array
                    // This array is not always populated, depending on the Content-Type header
                    $postFields = $request->post;
                }
            }
            if (!empty($postFields)) {
                $postFields = Normalizer::sanitizePostFields($postFields);
                foreach ($postFields as $key => $value) {
                    $rootSpan->meta["http.request.post.$key"] = $value;
                }
            }

            $normalizedPath = Normalizer::uriNormalizeincomingPath(
                $request->server['request_uri']
                ?? $request->server['path_info']
                ?? '/'
            );
            $rootSpan->resource = $request->server['request_method'] . ' ' . $normalizedPath;
            $rootSpan->meta[Tag::HTTP_METHOD] = $request->server['request_method'];

            $host = $headers['host'] ?? ($request->server['remote_addr'] . ':' . $request->server['server_port']);
            $path = $request->server['request_uri'] ?? $request->server['path_info'] ?? '';
            $query = isset($request->server['query_string']) ? '?' . $request->server['query_string'] : '';
            $url = 'https://' . $host . $path . $query;
            $rootSpan->meta[Tag::HTTP_URL] = Normalizer::uriNormalizeincomingPath($url);

            unset($rootSpan->meta['closure.declaration']);
        }
    );
}
