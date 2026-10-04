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
        return self::sourceTrace($peer, $forwarded, $configured)['source'];
    }

    private static function sourceTrace(string $peer, string $forwarded, string $configured): array
    {
        $normalize = static fn ($ip) => str_starts_with($ip, '::ffff:') ? substr($ip, 7) : $ip;
        $peer = $normalize($peer);
        if (!filter_var($peer, FILTER_VALIDATE_IP)) $peer = '0.0.0.0';
        $trusted = array_map($normalize, array_map('trim', preg_split('/[\s,]+/', $configured, -1, PREG_SPLIT_NO_EMPTY)));
        $address = $peer;
        $trustedHops = in_array($peer, $trusted, true) ? [$peer] : [];
        $hops = array_slice(explode(',', $forwarded), -16);
        foreach (array_reverse($hops) as $hop) {
            if (!in_array($address, $trusted, true)) break;
            $hop = $normalize(trim($hop));
            if (!filter_var($hop, FILTER_VALIDATE_IP)) break;
            $address = $hop;
            if (in_array($address, $trusted, true)) $trustedHops[] = $address;
        }
        return [
            'source' => ['ip' => $address, 'peer_ip' => $peer, 'ip_source' => $address === $peer ? 'peer' : 'trusted_proxy'],
            'trusted_hops' => $trustedHops,
        ];
    }

    public function mark($request): void
    {
        if (!$this->ready() || $request->attributes->has(self::MARKER)) return;
        $user = $request->user();
        if (!$user || !$user->id) return;
        $trace = self::sourceTrace((string) $request->server('REMOTE_ADDR', ''), (string) $request->header('X-Forwarded-For', ''), (string) ($this->options['trusted_proxies'] ?? ''));
        $source = $trace['source'];
        $proxyIp = trim((string) $request->header('X-Watch-Proxy-IP', ''));
        $proxyName = mb_strcut(trim((string) $request->header('X-Watch-Proxy-Name', '')), 0, 128, 'UTF-8');
        if (str_starts_with($proxyIp, '::ffff:')) $proxyIp = substr($proxyIp, 7);
        $proxyVerified = filter_var($proxyIp, FILTER_VALIDATE_IP)
            && $proxyIp !== $source['peer_ip']
            && in_array($proxyIp, $trace['trusted_hops'], true);
        if (!$proxyVerified) { $proxyIp = null; $proxyName = null; }
        elseif ($proxyName === '') $proxyName = null;
        $event = array_merge($source, [
            'proxy_ip' => $proxyIp, 'proxy_name' => $proxyName, 'proxy_verified' => (bool) $proxyVerified,
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

    public function review($request): array
    {
        $capture = $request->attributes->get(self::MARKER);
        if (!$this->ready() || !$capture) throw new \RuntimeException('review unavailable');
        $event = $capture['event'];
        $body = json_encode([
            'schema' => 1,
            'event_id' => $event['event_id'],
            'ts' => $event['ts'],
            'user_id' => $event['user_id'],
            'email' => $event['email'],
            'ip' => $event['ip'],
            'ua' => $event['ua'],
        ], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        $timestamp = (string) time();
        $secret = (string) $this->options['secret'];
        $signature = hash_hmac('sha256', $timestamp . "\n" . $body, $secret);
        $response = Http::connectTimeout(1)->timeout(4)->withoutRedirecting()
            ->withHeaders([
                'X-Watch-Timestamp' => $timestamp,
                'X-Watch-Signature' => $signature,
                'X-Watch-Panel' => (string) ($this->options['panel_id'] ?? ''),
            ])
            ->withBody($body, 'application/json')
            ->post(rtrim($this->options['endpoint'], '/') . '/api/collector/review');
        if ($response->status() >= 400 && $response->status() < 500)
            throw new \UnexpectedValueException('review authentication or request rejected');
        if ($response->status() !== 200) throw new \RuntimeException('review unavailable');
        $signed = (string) $response->header('X-Watch-Decision-Signature');
        if (!preg_match('/^[a-f0-9]{64}$/', $signed)
            || !hash_equals(hash_hmac('sha256', $response->body(), $secret), $signed))
            throw new \UnexpectedValueException('review signature invalid');
        $answer = $response->json();
        if (!is_array($answer) || ($answer['event_id'] ?? null) !== $event['event_id']
            || !is_bool($answer['allow'] ?? null))
            throw new \UnexpectedValueException('review response invalid');
        if (!$answer['allow']) {
            $target = (string) ($answer['redirect'] ?? '');
            $parts = parse_url($target);
            if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
                || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
                || preg_match('/[\r\n]/', $target))
                throw new \UnexpectedValueException('review redirect invalid');
            return ['allow' => false, 'redirect' => $target];
        }
        return ['allow' => true, 'redirect' => null];
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
                $payload = json_encode(['schema' => 1, 'version' => '4.0.7', 'metrics' => $buffer->metrics(), 'events' => $events], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
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
