<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Log;

// Only notifications and the scheduler write these tables. Link generation performs one local read per request.
class OriginStore
{
    public function __construct(private array $options) {}

    private function scope(): string
    {
        $panel = (string) ($this->options['panel_id'] ?? '');
        $secret = (string) ($this->options['secret'] ?? '');
        if (!preg_match('/^[a-f0-9]{48}$/D', $panel) || strlen($secret) < 32) throw new \InvalidArgumentException('Invalid configuration');
        return hash('sha256', $panel . '|' . $secret);
    }

    public static function validOrigin($origin): bool
    {
        if (!is_string($origin) || strlen($origin) > 255 || preg_match('/[\s\\\\]/', $origin)
            || !preg_match('#^https://[^/?\#]+/?$#D', $origin)) return false;
        $p = parse_url($origin);
        return is_array($p) && ($p['scheme'] ?? '') === 'https' && !empty($p['host'])
            && !isset($p['user']) && !isset($p['pass']) && !isset($p['query']) && !isset($p['fragment'])
            && in_array($p['path'] ?? '', ['', '/'], true);
    }

    public function origins(): array
    {
        $scope = $this->scope();
        $attributes = request()->attributes;
        $key = '_watch_local_origins_' . $scope;
        if ($attributes->has($key)) return $attributes->get($key);
        $attributes->set($key, []);
        $rows = DB::table('subscription_watch_origins as o')
            ->join((new User())->getTable() . ' as u', 'u.id', '=', 'o.uid')->where('o.scope', $scope)
            ->get(['u.token', 'u.email as current_email', 'o.email', 'o.origin']);
        $origins = [];
        foreach ($rows as $row) {
            if ((string) $row->current_email !== (string) $row->email || !self::validOrigin($row->origin)
                || !preg_match('/^[a-f0-9]{32}$/iD', (string) $row->token)) continue;
            $origins[strtolower($row->token)] = rtrim($row->origin, '/');
        }
        $attributes->set($key, $origins);
        return $origins;
    }

    private function initialize(): void
    {
        if (!Schema::hasTable('subscription_watch_origins')) Schema::create('subscription_watch_origins', static function ($table) {
            $table->string('scope', 64); $table->unsignedBigInteger('uid');
            $table->string('email', 254); $table->string('origin', 255); $table->primary(['scope', 'uid']);
        });
        if (!Schema::hasTable('subscription_watch_origin_state')) Schema::create('subscription_watch_origin_state', static function ($table) {
            $table->string('scope', 64)->primary(); $table->string('revision', 64);
        });
    }

    private function page(?string $revision, int $cursor): array
    {
        $panel = (string) $this->options['panel_id']; $secret = (string) $this->options['secret'];
        $nonce = bin2hex(random_bytes(24)); $timestamp = (string) time();
        $body = json_encode(['schema' => 1, 'nonce' => $nonce, 'revision' => $revision, 'cursor' => $cursor], JSON_THROW_ON_ERROR);
        $response = Endpoints::post(Endpoints::parse((string) ($this->options['endpoint'] ?? '')),
            '/api/collector/subscription-origin-sync', $body, ['X-Watch-Panel' => $panel, 'X-Watch-Timestamp' => $timestamp,
                'X-Watch-Signature' => hash_hmac('sha256', "subscription-origin-sync-request\n" . $timestamp . "\n" . $body, $secret)], 5.0);
        if (!$response->successful() || strlen($response->body()) > 1048576) throw new \UnexpectedValueException('Invalid response');
        $envelope = $response->json();
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null) || !is_string($envelope['signature'] ?? null)
            || !hash_equals(hash_hmac('sha256', "subscription-origin-sync-response\n" . $envelope['payload'], $secret), $envelope['signature']))
            throw new \UnexpectedValueException('Invalid signature');
        $raw = base64_decode($envelope['payload'], true);
        $data = $raw === false ? null : json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        $now = (int) round(microtime(true) * 1000);
        if (!is_array($data) || ($data['schema'] ?? null) !== 1 || ($data['panel'] ?? null) !== $panel || ($data['nonce'] ?? null) !== $nonce
            || !is_int($data['expires'] ?? null) || $data['expires'] < $now || $data['expires'] > $now + 60000
            || !is_string($data['revision'] ?? null) || !preg_match('/^[a-f0-9]{64}$/D', $data['revision'])
            || !is_bool($data['restart'] ?? null) || !is_bool($data['unchanged'] ?? null)
            || !array_key_exists('next', $data) || ($data['next'] !== null && (!is_int($data['next']) || $data['next'] <= $cursor))
            || !is_array($data['users'] ?? null) || count($data['users']) > 500) throw new \UnexpectedValueException('Invalid response');
        return $data;
    }

    private function synchronize(): string
    {
        $scope = $this->scope();
        $this->initialize();
        $previous = DB::table('subscription_watch_origin_state')->where('scope', $scope)->value('revision');
        $revision = $previous; $cursor = 0; $rows = []; $deadline = microtime(true) + 45;
        for ($page = 0; $page < 100 && microtime(true) < $deadline; $page++) {
            $data = $this->page($revision, $cursor);
            if ($data['restart']) throw new \RuntimeException('Snapshot changed');
            if ($data['unchanged']) {
                if ($cursor !== 0 || $data['revision'] !== $previous || $data['users'] !== [] || $data['next'] !== null)
                    throw new \UnexpectedValueException('Invalid unchanged response');
                return $previous;
            }
            if ($cursor > 0 && $data['revision'] !== $revision) throw new \UnexpectedValueException('Mixed snapshot');
            $revision = $data['revision']; $last = $cursor;
            foreach ($data['users'] as $user) {
                if (!is_array($user) || !is_int($user['user_id'] ?? null) || $user['user_id'] <= $last
                    || !is_string($user['email'] ?? null) || strlen($user['email']) > 254 || !preg_match('/^[^\s@]+@[^\s@]+$/uD', $user['email'])
                    || !self::validOrigin($user['origin'] ?? null)) throw new \UnexpectedValueException('Invalid mapping');
                $last = $user['user_id'];
                $rows[] = ['scope' => $scope, 'uid' => $last, 'email' => $user['email'], 'origin' => rtrim($user['origin'], '/')];
            }
            if ($data['next'] !== null) {
                if ($data['next'] !== $last || count($data['users']) !== 500) throw new \UnexpectedValueException('Invalid cursor');
                $cursor = $last; continue;
            }
            DB::transaction(static function () use ($scope, $revision, $rows) {
                DB::table('subscription_watch_origins')->where('scope', $scope)->delete();
                foreach (array_chunk($rows, 200) as $chunk) DB::table('subscription_watch_origins')->insert($chunk);
                DB::table('subscription_watch_origin_state')->updateOrInsert(['scope' => $scope], ['revision' => $revision]);
            });
            return $revision;
        }
        throw new \RuntimeException('Sync budget exhausted');
    }

    private function run(): string
    {
        $key = 'origin-sync:' . $this->scope(); $token = bin2hex(random_bytes(24));
        $redis = (new Buffer($this->options))->controlConnection();
        if (!(int) $redis->eval("if redis.call('EXISTS',KEYS[1])==0 then redis.call('SET',KEYS[1],ARGV[1],'EX',60); return 1 end return 0", 1, $key, $token))
            throw new \RuntimeException('Sync busy');
        try { return $this->synchronize(); }
        finally { $redis->eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", 1, $key, $token); }
    }

    public function poll(): void
    {
        try { $revision = $this->run(); $this->page($revision, 0); }
        catch (\Throwable $e) { Log::warning('Subscription Watch local address sync pending', ['code' => 'sync-unavailable']); }
    }

    public function notify($request, bool $lookup = false)
    {
        $domain = $lookup ? 'subscription-origin-lookup' : 'subscription-origin-notify';
        $panel = (string) ($this->options['panel_id'] ?? ''); $secret = (string) ($this->options['secret'] ?? '');
        $timestamp = $request->header('X-Watch-Timestamp'); $signature = $request->header('X-Watch-Signature'); $raw = $request->getContent();
        if (strlen($secret) < 32 || !preg_match('/^[a-f0-9]{48}$/D', $panel) || $request->header('X-Watch-Panel') !== $panel
            || !is_string($timestamp) || !preg_match('/^\d{10}$/D', $timestamp) || abs(time() - (int) $timestamp) > 300
            || !is_string($signature) || !is_string($raw) || strlen($raw) > 1024
            || !hash_equals(hash_hmac('sha256', $domain . "-request\n" . $timestamp . "\n" . $raw, $secret), $signature))
            return response()->json(['error' => 'invalid signature'], 401);
        try { $event = json_decode($raw, true, 8, JSON_THROW_ON_ERROR); }
        catch (\Throwable $e) { return response()->json(['error' => 'invalid request'], 422); }
        if (!is_array($event) || ($event['schema'] ?? null) !== 1 || !is_string($event['nonce'] ?? null)
            || !preg_match('/^[a-f0-9]{48}$/D', $event['nonce']) || count($event) !== ($lookup ? 3 : 2)) return response()->json(['error' => 'invalid request'], 422);
        try {
            if ($lookup) {
                $query = $event['query'] ?? null;
                if (!is_string($query) || strlen($query) > 254 || !preg_match('/^(?:[1-9][0-9]{0,14}|[^\s@]+@[^\s@]+)$/uD', $query))
                    return response()->json(['error' => 'invalid query'], 422);
                $user = User::query()->where(ctype_digit($query) ? 'id' : 'email', $query)->first(['id', 'email', 'token']);
                $result = ['query' => $query, 'user' => $user ? ['id' => (int) $user->id, 'email' => (string) $user->email,
                    'subscribe_url' => (new SubscriptionOrigin($this->options))->rewrite(\App\Utils\Helper::getSubscribeUrl((string) $user->token))] : null];
            } else $result = ['revision' => $this->run()];
            $payload = base64_encode(json_encode(['schema' => 1, 'panel' => $panel, 'nonce' => $event['nonce'],
                ...$result, 'expires' => (int) round(microtime(true) * 1000) + 30000], JSON_THROW_ON_ERROR));
            return response()->json(['payload' => $payload, 'signature' => hash_hmac('sha256', $domain . "-response\n" . $payload, $secret)])
                ->header('Cache-Control', 'no-store');
        } catch (\Throwable $e) {
            Log::warning('Subscription Watch local address sync pending', ['code' => 'sync-unavailable']);
            return response()->json(['error' => 'sync pending'], 503);
        }
    }
}
