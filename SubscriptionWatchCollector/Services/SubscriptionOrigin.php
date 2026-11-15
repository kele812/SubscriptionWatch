<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use Illuminate\Support\Facades\Log;

// Filters generated links using the synchronized local database. Never calls the watch service.
class SubscriptionOrigin
{
    public function __construct(private array $options) {}

    public static function mark($request, array $options): void
    {
        $request->attributes->set('_watch_subscription_origin_options', $options);
    }

    // Compatibility path for Xboard versions/themes that bypass the subscribe.url helper filter.
    // Request-local options avoid retaining another Octane request's panel configuration.
    public static function handled($event): void
    {
        try {
            $request = $event->request;
            $options = $request->attributes->get('_watch_subscription_origin_options');
            $path = trim($request->path(), '/');
            if (!is_array($options) || !preg_match('#^api/v[12]/(?:[^/]+/)?user/(fetch|getUserInfoById|getSubscribe|resetSecurity)$#D', $path)) return;
            $response = $event->response;
            if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300
                || !str_contains(strtolower((string) $response->headers->get('Content-Type')), 'application/json')) return;
            $raw = $response->getContent();
            if (!is_string($raw) || strlen($raw) > 1048576) return;
            $data = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($data)) return;
            $service = new self($options);
            $changed = false; $found = false; $remaining = 4000;
            $walk = function (array &$node, int $depth = 0) use (&$walk, $service, &$changed, &$found, &$remaining) {
                if ($depth > 8 || --$remaining < 0) return;
                foreach ($node as $key => &$value) {
                    if ($key === 'subscribe_url' && is_string($value)) {
                        $found = true;
                        $replacement = $service->rewrite($value);
                        if ($replacement !== $value) { $value = $replacement; $changed = true; }
                    } elseif (is_array($value)) $walk($value, $depth + 1);
                }
                unset($value);
            };
            $walk($data);
            if (str_ends_with($path, '/resetSecurity') && is_string($data['data'] ?? null)) {
                $found = true;
                $replacement = $service->rewrite($data['data']);
                if ($replacement !== $data['data']) { $data['data'] = $replacement; $changed = true; }
            }
            if (!$found) return;
            if ($changed) {
                $response->setContent(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
                $response->headers->remove('Content-Length');
            }
            $response->headers->remove('ETag');
            $response->headers->set('Cache-Control', 'private, no-store');
        } catch (\Throwable $e) {
            // Never turn an admin/user API response into an error or log its sensitive body.
        }
    }

    private static function warning(string $code, int $uid): void
    {
        try {
            $key = '_watch_subscription_origin_warning';
            if (request()->attributes->has($key)) return;
            request()->attributes->set($key, true);
            Log::warning('Subscription Watch subscription URL lookup failed', ['code' => $code, 'user_id' => $uid]);
        } catch (\Throwable $e) {}
    }

    public function rewrite($url)
    {
        if (!is_string($url)) return $url;
        $uid = 0;
        try {
            $parts = parse_url($url);
            if (!is_array($parts) || empty($parts['host']) || !in_array($parts['scheme'] ?? '', ['https', 'http'], true)) return $url;
            parse_str($parts['query'] ?? '', $query);
            // Current Xboard defaults to /s/{token}; legacy installs use ?token=...
            // A route path token takes precedence over an unrelated query parameter.
            $lastSegment = basename(rtrim($parts['path'] ?? '', '/'));
            $token = preg_match('/^[a-f0-9]{32}$/iD', $lastSegment) ? $lastSegment : ($query['token'] ?? null);
            if (!is_string($token) || !preg_match('/^[a-f0-9]{32}$/iD', $token)) return $url;
            $origin = (new OriginStore($this->options))->origins()[strtolower($token)] ?? null;
            if ($origin === null) return $url;
            return $origin . ($parts['path'] ?? '')
                . (isset($parts['query']) ? '?' . $parts['query'] : '')
                . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
        } catch (\Throwable $e) {
            self::warning($e instanceof ReviewUnavailable ? 'unavailable' : 'lookup-error', $uid);
            // A lookup outage must not stop the dashboard. Use Xboard's own generated URL.
            return $url;
        }
    }

}
