<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use App\Models\User;
use Illuminate\Support\Facades\Log;

// Filters generated links. Tokens are resolved locally and never sent to the watch service.
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
            // Resolve the URL owner, not a logged-in administrator or another Octane request's user.
            $user = User::query()->where('token', $token)->first(['id', 'email']);
            if (!$user || (int) $user->id < 1 || !is_string($user->email)) return $url;
            $uid = (int) $user->id;
            $origin = $this->origin($uid, $user->email);
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

    private function origin(int $uid, string $email): ?string
    {
        $endpoints = Endpoints::parse((string) ($this->options['endpoint'] ?? ''));
        $panel = (string) ($this->options['panel_id'] ?? '');
        $secret = (string) ($this->options['secret'] ?? '');
        if (!preg_match('/^[a-f0-9]{48}$/D', $panel) || strlen($secret) < 32) {
            self::warning('configuration-invalid', $uid); return null;
        }
        // Request-local only: a new customer request always sees current settings and removals.
        $cacheKey = '_watch_subscription_origin_' . hash('sha256', implode('|', $endpoints) . '|' . $panel . '|' . $secret . '|' . $uid . '|' . $email);
        $attributes = request()->attributes;
        if ($attributes->has($cacheKey)) return $attributes->get($cacheKey);
        $attributes->set($cacheKey, null);
        $unavailableKey = '_watch_subscription_origin_unavailable_' . hash('sha256', implode('|', $endpoints) . '|' . $panel . '|' . $secret);
        if ($attributes->has($unavailableKey)) return null;
        $nonce = bin2hex(random_bytes(24));
        $timestamp = (string) time();
        $body = json_encode(['schema' => 1, 'user_id' => $uid, 'email' => $email, 'nonce' => $nonce], JSON_THROW_ON_ERROR);
        try {
            $response = Endpoints::post($endpoints, '/api/collector/subscription-origin', $body, [
                'X-Watch-Panel' => $panel,
                'X-Watch-Timestamp' => $timestamp,
                'X-Watch-Signature' => hash_hmac('sha256', "subscription-origin-request\n" . $timestamp . "\n" . $body, $secret),
            ], 2.5);
        } catch (ReviewUnavailable $e) {
            $attributes->set($unavailableKey, true);
            self::warning('unavailable', $uid); return null;
        }
        if (!$response->successful()) {
            if (in_array($response->status(), [401, 403, 404], true)) $attributes->set($unavailableKey, true);
            self::warning('http-' . $response->status(), $uid); return null;
        }
        if (strlen($response->body()) > 8192) { self::warning('response-too-large', $uid); return null; }
        $envelope = $response->json();
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null) || !is_string($envelope['signature'] ?? null)
            || !hash_equals(hash_hmac('sha256', "subscription-origin-response\n" . $envelope['payload'], $secret), $envelope['signature'])) {
            $attributes->set($unavailableKey, true);
            self::warning('response-signature-invalid', $uid); return null;
        }
        $decoded = base64_decode($envelope['payload'], true);
        if ($decoded === false) return null;
        $data = json_decode($decoded, true, 16, JSON_THROW_ON_ERROR);
        $now = (int) round(microtime(true) * 1000);
        if (!is_array($data) || ($data['schema'] ?? null) !== 1 || ($data['panel'] ?? null) !== $panel
            || ($data['nonce'] ?? null) !== $nonce || ($data['user_id'] ?? null) !== $uid || ($data['email'] ?? null) !== $email
            || !is_int($data['expires'] ?? null) || $data['expires'] < $now || $data['expires'] > $now + 60000) {
            self::warning('response-invalid-or-expired', $uid); return null;
        }
        if (($data['lookup_status'] ?? null) === 'email-mismatch') { self::warning('email-mismatch', $uid); return null; }
        $origin = $data['origin'] ?? null;
        if ($origin === null) return null;
        if (!is_string($origin) || strlen($origin) > 255 || preg_match('/[\s\\\\]/', $origin)) return null;
        $parsed = parse_url($origin);
        if (!is_array($parsed) || ($parsed['scheme'] ?? '') !== 'https' || empty($parsed['host'])
            || isset($parsed['user']) || isset($parsed['pass']) || isset($parsed['query']) || isset($parsed['fragment'])
            || !in_array($parsed['path'] ?? '', ['', '/'], true)) return null;
        $origin = rtrim($origin, '/');
        $attributes->set($cacheKey, $origin);
        return $origin;
    }
}
