<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use Illuminate\Support\Facades\Http;

class Collector
{
    private array $options;
    private const MARKER = '_subscription_watch_capture';
    public function __construct(array $options) { $this->options = $options; }

    private function ready(): bool
    {
        $url = parse_url((string) ($this->options['endpoint'] ?? ''));
        return is_array($url) && ($url['scheme'] ?? '') === 'https' && !empty($url['host'])
            && empty($url['user']) && empty($url['pass']) && empty($url['query']) && empty($url['fragment'])
            && in_array($url['path'] ?? '', ['', '/'], true) && strlen((string) ($this->options['secret'] ?? '')) >= 32;
    }

    public static function sourceIp(string $peer, string $forwarded, string $configured): array
    {
        $normalize = static fn ($ip) => str_starts_with($ip, '::ffff:') ? substr($ip, 7) : $ip;
        $peer = $normalize($peer);
        if (!filter_var($peer, FILTER_VALIDATE_IP)) $peer = '0.0.0.0';
        $trusted = array_map($normalize, array_map('trim', preg_split('/[\s,]+/', $configured, -1, PREG_SPLIT_NO_EMPTY)));
        $address = $peer;
        $hops = array_slice(explode(',', $forwarded), -16);
        foreach (array_reverse($hops) as $hop) {
            if (!in_array($address, $trusted, true)) break;
            $hop = $normalize(trim($hop));
            if (!filter_var($hop, FILTER_VALIDATE_IP)) break;
            $address = $hop;
        }
        return ['ip' => $address, 'peer_ip' => $peer, 'ip_source' => $address === $peer ? 'peer' : 'trusted_proxy'];
    }

    public function mark($request): void
    {
        if (!$this->ready() || $request->attributes->has(self::MARKER)) return;
        $user = $request->user();
        if (!$user || !$user->id) return;
        $source = self::sourceIp((string) $request->server('REMOTE_ADDR', ''), (string) $request->header('X-Forwarded-For', ''), (string) ($this->options['trusted_proxies'] ?? ''));
        $event = array_merge($source, [
            'event_id' => bin2hex(random_bytes(16)), 'ts' => (int) round(microtime(true) * 1000),
            'user_id' => (int) $user->id, 'email' => mb_strcut((string) $user->email, 0, 254, 'UTF-8'),
            'ua' => mb_strcut((string) $request->header('User-Agent', ''), 0, 1024, 'UTF-8'),
            'flag' => is_string($request->input('flag')) ? mb_strcut($request->input('flag'), 0, 128, 'UTF-8') : '',
        ]);
        // Correlate requests for the same subscription without sending or storing its raw token.
        $subscriptionToken = (string) ($user->token ?? '');
        if ($subscriptionToken !== '') {
            $event['token_fingerprint'] = hash_hmac('sha256', $subscriptionToken, (string) $this->options['secret']);
        }
        $request->attributes->set(self::MARKER, ['collector' => $this, 'event' => $event, 'start' => microtime(true)]);
    }

    public static function handled($handled): void
    {
        try {
            $request = $handled->request;
            $capture = $request->attributes->get(self::MARKER);
            if (!$capture) return;
            $request->attributes->remove(self::MARKER);
            $event = $capture['event'];
            $event['status'] = $handled->response->getStatusCode();
            $event['ms'] = min(3600000, max(0, (int) round((microtime(true) - $capture['start']) * 1000)));
            // Do not materialize or serialize subscription response bodies.
            $length = $handled->response->headers->get('Content-Length');
            $event['bytes'] = is_string($length) && ctype_digit($length) ? (int) $length : null;
            $contentType = strtolower(trim((string) $handled->response->headers->get('Content-Type', '')));
            $event['content_type'] = substr($contentType, 0, 128);
            $event['delivered'] = $event['status'] >= 200 && $event['status'] < 300
                && $event['bytes'] !== 0
                && !str_contains($contentType, 'text/html');
            (new Buffer($capture['collector']->options))->enqueue($event);
        } catch (\Throwable $e) {}
    }

    public function flush(): void
    {
        if (!$this->ready()) return;
        $buffer = new Buffer($this->options);
        $token = bin2hex(random_bytes(16));
        try {
            if (!$buffer->lock($token)) return;
            // At most three batches / minute; failed batches stay in Redis until their expiry.
            for ($i = 0; $i < 3; $i++) {
                $members = $buffer->batch();
                $events = array_map(static fn ($item) => json_decode($item, true, 512, JSON_THROW_ON_ERROR), $members);
                $payload = json_encode(['schema' => 1, 'version' => '3.8.7', 'metrics' => $buffer->metrics(), 'events' => $events], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
                $timestamp = (string) time();
                $signature = hash_hmac('sha256', $timestamp . "\n" . $payload, (string) $this->options['secret']);
                $response = Http::connectTimeout(1)->timeout(3)->withoutRedirecting()
                    ->withHeaders(['X-Watch-Timestamp' => $timestamp, 'X-Watch-Signature' => $signature, 'X-Watch-Panel' => (string) ($this->options['panel_id'] ?? '')])
                    ->withBody($payload, 'application/json')->post(rtrim($this->options['endpoint'], '/') . '/api/collector/events');
                if (!$response->successful() || $response->json('ok') !== true || $response->json('accepted') !== count($members)) { $buffer->uploadFailed(); break; }
                $buffer->acknowledge($members, $token);
                if (count($members) < 100) break;
            }
        } catch (\Throwable $e) {
            // Deliberately do not log exception messages: HTTP exceptions can include personal data or secrets.
            $buffer->uploadFailed();
        } finally {
            try { $buffer->unlock($token); } catch (\Throwable $e) {}
        }
    }
}
