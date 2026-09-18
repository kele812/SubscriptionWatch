<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use App\Models\User;
use App\Services\AuthService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

// Runs only in the minute scheduler, never in a customer's subscription request.
class Control
{
    private array $options;
    public function __construct(array $options) { $this->options = $options; }

    public function poll(): void
    {
        $endpoint = rtrim((string) ($this->options['endpoint'] ?? ''), '/');
        $url = parse_url($endpoint);
        $secret = (string) ($this->options['secret'] ?? '');
        $panel = (string) ($this->options['panel_id'] ?? '');
        if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' || empty($url['host'])
            || !empty($url['user']) || !empty($url['pass']) || !empty($url['query']) || !empty($url['fragment'])
            || !in_array($url['path'] ?? '', ['', '/'], true) || strlen($secret) < 32 || !preg_match('/^[a-f0-9]{48}$/D', $panel)) return;
        $redis = (new Buffer($this->options))->controlConnection();
        // Namespace results by destination and key, never mix two panel configurations.
        $prefix = 'control:' . substr(hash('sha256', $endpoint . '|' . $panel . '|' . $secret), 0, 24) . ':';
        $lock = bin2hex(random_bytes(24));
        if (!(int) $redis->eval("if redis.call('EXISTS',KEYS[1])==0 then redis.call('SET',KEYS[1],ARGV[1],'EX',60); return 1 end return 0", 1, $prefix . 'lock', $lock)) return;
        try {
            $this->exchange($redis, $prefix, $endpoint, $panel, $secret, true);
            // Send results promptly, without taking more tasks in the same scheduler run.
            if ((int) $redis->hlen($prefix . 'results') > 0) $this->exchange($redis, $prefix, $endpoint, $panel, $secret, false);
        } finally {
            $redis->eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", 1, $prefix . 'lock', $lock);
        }
    }

    private function exchange($redis, string $prefix, string $endpoint, string $panel, string $secret, bool $take): void
    {
        $pending = array_slice($redis->hgetall($prefix . 'results'), 0, 10, true);
        $results = [];
        foreach ($pending as $id => $status) $results[] = ['id' => $id, 'status' => $status];
        $nonce = bin2hex(random_bytes(24));
        $payload = json_encode(['schema' => 1, 'capability' => 'ban-v2', 'version' => '3.7.0', 'nonce' => $nonce,
            'acceptTasks' => $take && (int) $redis->hlen($prefix . 'results') < 90, 'results' => $results], JSON_THROW_ON_ERROR);
        $timestamp = (string) time();
        $response = Http::connectTimeout(2)->timeout(5)->withoutRedirecting()->withHeaders([
            'X-Watch-Panel' => $panel, 'X-Watch-Timestamp' => $timestamp,
            'X-Watch-Signature' => hash_hmac('sha256', "control-request\n" . $timestamp . "\n" . $payload, $secret),
        ])->withBody($payload, 'application/json')->post($endpoint . '/api/collector/control');
        if (!$response->successful() || strlen($response->body()) > 32768) return;
        $envelope = $response->json();
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null) || !is_string($envelope['signature'] ?? null)
            || !hash_equals(hash_hmac('sha256', "control-response\n" . $envelope['payload'], $secret), $envelope['signature'])) return;
        $decoded = base64_decode($envelope['payload'], true);
        if ($decoded === false) return;
        $data = json_decode($decoded, true, 32, JSON_THROW_ON_ERROR);
        $now = (int) round(microtime(true) * 1000);
        if (($data['schema'] ?? null) !== 1 || ($data['panel'] ?? '') !== $panel || ($data['nonce'] ?? '') !== $nonce
            || !is_int($data['expires'] ?? null) || $data['expires'] < $now || $data['expires'] > $now + 60000
            || !is_array($data['tasks'] ?? null) || count($data['tasks']) > 3 || !is_array($data['acknowledged'] ?? null)) return;
        foreach ($data['acknowledged'] as $id) if (is_string($id) && isset($pending[$id])) $redis->hdel($prefix . 'results', $id);
        foreach ($data['tasks'] as $task) {
            if (!$take || !is_array($task) || !in_array($task['action'] ?? '', ['ban', 'unban'], true)
                || !is_string($task['id'] ?? null) || !preg_match('/^[a-f0-9]{48}$/D', $task['id'])
                || !is_int($task['user_id'] ?? null) || $task['user_id'] < 1 || !is_string($task['email'] ?? null)
                || strlen($task['email']) < 1 || strlen($task['email']) > 254 || !is_int($task['expires'] ?? null)
                || $task['expires'] > $data['expires']) continue;
            // Reserve before touching SQL. A crash is reported as unknown/failed, never retried.
            $reserved = $redis->eval("if redis.call('EXISTS',KEYS[1])==1 or redis.call('HLEN',KEYS[2])>=100 then return 0 end redis.call('SET',KEYS[1],'1','EX',604800); redis.call('HSET',KEYS[2],ARGV[1],'failed'); redis.call('EXPIRE',KEYS[2],604800); return 1", 2, $prefix . 'seen:' . $task['id'], $prefix . 'results', $task['id']);
            if (!(int) $reserved) continue;
            $result = 'failed';
            try { $result = self::execute($task); } catch (\Throwable $e) {}
            $redis->hset($prefix . 'results', $task['id'], $result);
        }
    }

    private static function execute(array $task): string
    {
        if (!in_array($task['action'] ?? '', ['ban','unban'], true)) return 'rejected';
        return DB::transaction(static function () use ($task) {
            $user = User::query()->whereKey($task['user_id'])->lockForUpdate()->first();
            if ($task['expires'] < (int) round(microtime(true) * 1000)) return 'expired';
            if (!$user || (string) $user->email !== $task['email'] || (bool) $user->is_admin || (bool) $user->is_staff) return 'rejected';
            if (($task['action'] ?? '') === 'unban') {
                if (!(bool) $user->banned) return 'already_unbanned';
                $user->banned = 0;
                if (!$user->save()) throw new \RuntimeException('Save failed');
                return 'unbanned';
            }
            if ((bool) $user->banned) return 'already_banned';
            $user->banned = 1;
            if (!$user->save()) throw new \RuntimeException('Save failed');
            // Match Xboard's own single-user ban session invalidation, preserving every other user field.
            if (!(new AuthService($user))->removeAllSessions()) throw new \RuntimeException('Session removal failed');
            return 'banned';
        });
    }
}
