<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use App\Models\User;

// Filters generated links. Tokens are resolved locally and never sent to the watch service.
class SubscriptionOrigin
{
    public function __construct(private array $options) {}

    public function rewrite($url)
    {
        if (!is_string($url)) return $url;
        try {
            $parts = parse_url($url);
            if (!is_array($parts) || empty($parts['host']) || !in_array($parts['scheme'] ?? '', ['https', 'http'], true)) return $url;
            parse_str($parts['query'] ?? '', $query);
            $token = $query['token'] ?? null;
            if (!is_string($token) || !preg_match('/^[a-f0-9]{32}$/iD', $token)) return $url;
            // Resolve the URL owner, not a logged-in administrator or another Octane request's user.
            $user = User::query()->where('token', $token)->first(['id', 'email']);
            if (!$user || (int) $user->id < 1 || !is_string($user->email)) return $url;
            $origin = $this->origin((int) $user->id, $user->email);
            if ($origin === null) return $url;
            return $origin . ($parts['path'] ?? '')
                . (isset($parts['query']) ? '?' . $parts['query'] : '')
                . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
        } catch (\Throwable $e) {
            // A lookup outage must not stop the dashboard. Use Xboard's own generated URL.
            return $url;
        }
    }

    private function origin(int $uid, string $email): ?string
    {
        $endpoints = Endpoints::parse((string) ($this->options['endpoint'] ?? ''));
        $panel = (string) ($this->options['panel_id'] ?? '');
        $secret = (string) ($this->options['secret'] ?? '');
        if (!preg_match('/^[a-f0-9]{48}$/D', $panel) || strlen($secret) < 32) return null;
        // Request-local only: a new customer request always sees current settings and removals.
        $cacheKey = '_watch_subscription_origin_' . hash('sha256', implode('|', $endpoints) . '|' . $panel . '|' . $secret . '|' . $uid . '|' . $email);
        $attributes = request()->attributes;
        if ($attributes->has($cacheKey)) return $attributes->get($cacheKey);
        $attributes->set($cacheKey, null);
        $nonce = bin2hex(random_bytes(24));
        $timestamp = (string) time();
        $body = json_encode(['schema' => 1, 'user_id' => $uid, 'email' => $email, 'nonce' => $nonce], JSON_THROW_ON_ERROR);
        $response = Endpoints::post($endpoints, '/api/collector/subscription-origin', $body, [
            'X-Watch-Panel' => $panel,
            'X-Watch-Timestamp' => $timestamp,
            'X-Watch-Signature' => hash_hmac('sha256', "subscription-origin-request\n" . $timestamp . "\n" . $body, $secret),
        ], 2.5);
        if (!$response->successful() || strlen($response->body()) > 8192) return null;
        $envelope = $response->json();
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null) || !is_string($envelope['signature'] ?? null)
            || !hash_equals(hash_hmac('sha256', "subscription-origin-response\n" . $envelope['payload'], $secret), $envelope['signature'])) return null;
        $decoded = base64_decode($envelope['payload'], true);
        if ($decoded === false) return null;
        $data = json_decode($decoded, true, 16, JSON_THROW_ON_ERROR);
        $now = (int) round(microtime(true) * 1000);
        if (!is_array($data) || ($data['schema'] ?? null) !== 1 || ($data['panel'] ?? null) !== $panel
            || ($data['nonce'] ?? null) !== $nonce || ($data['user_id'] ?? null) !== $uid || ($data['email'] ?? null) !== $email
            || !is_int($data['expires'] ?? null) || $data['expires'] < $now || $data['expires'] > $now + 60000) return null;
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
