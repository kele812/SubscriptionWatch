<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use Illuminate\Redis\RedisManager;

class Buffer
{
    private static ?RedisManager $manager = null;
    private static float $disabledUntil = 0;
    private static int $localDrops = 0;
    private $redis;
    private int $limit;
    private int $ttl;

    public function __construct(array $options)
    {
        $this->limit = max(100, min(10000, (int) ($options['queue_limit'] ?? 2000)));
        $this->ttl = max(300, min(86400, (int) ($options['retention_seconds'] ?? 3600)));
    }

    private function connection()
    {
        if (microtime(true) < self::$disabledUntil) throw new \RuntimeException('Redis circuit open');
        if (!self::$manager) {
            $config = config('database.redis.default');
            if (!is_array($config)) throw new \RuntimeException('Redis configuration missing');
            // Dedicated connection: never alter timeouts or serialization of Xboard's shared Redis connection.
            $config = array_merge($config, ['timeout' => 0.15, 'read_timeout' => 0.15,
                'read_write_timeout' => 0.15, 'retry_interval' => 0, 'max_retries' => 0, 'persistent' => false]);
            $prefix = 'swc:' . substr(hash('sha256', (string) config('app.key')), 0, 12) . ':';
            self::$manager = new RedisManager(app(), config('database.redis.client', 'phpredis'), [
                'options' => ['prefix' => $prefix], 'default' => $config,
            ]);
        }
        return self::$manager->connection();
    }

    private static function failed(): void
    {
        self::$disabledUntil = microtime(true) + 30;
        self::$manager = null;
    }

    public function enqueue(array $event): void
    {
        try {
            $redis = $this->connection();
            $json = json_encode($event, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
            // The per-event expiry is the sorted-set score. UUID makes each JSON member unique.
            $script = <<<'LUA'
local expired = redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
if expired > 0 then redis.call('INCRBY', KEYS[3], expired) end
if tonumber(ARGV[6]) > 0 then redis.call('INCRBY', KEYS[2], ARGV[6]) end
redis.call('EXPIRE', KEYS[2], 604800)
redis.call('EXPIRE', KEYS[3], 604800)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
 redis.call('INCR', KEYS[2]); redis.call('EXPIRE', KEYS[2], 604800); return 0
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
LUA;
            $redis->eval($script, 3, 'pending', 'dropped', 'expired', time(), time() + $this->ttl, $this->limit, $json, $this->ttl + 60, self::$localDrops);
            self::$localDrops = 0;
        } catch (\Throwable $e) {
            self::$localDrops++;
            if (microtime(true) >= self::$disabledUntil) self::failed();
        }
    }

    public function lock(string $token): bool
    {
        $this->redis = $this->connection();
        return (int) $this->redis->eval("if redis.call('EXISTS',KEYS[1])==0 then redis.call('SET',KEYS[1],ARGV[1],'EX',30); return 1 end return 0", 1, 'flush-lock', $token) === 1;
    }

    public function batch(): array
    {
        $this->redis->eval("local n=redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',ARGV[1]); if n>0 then redis.call('INCRBY',KEYS[2],n); redis.call('EXPIRE',KEYS[2],604800) end return n", 2, 'pending', 'expired', time());
        return $this->redis->zrange('pending', 0, 99);
    }

    public function metrics(): array
    {
        return ['pending' => (int) $this->redis->zcard('pending'),
            'dropped' => (int) ($this->redis->get('dropped') ?: 0),
            'expired' => (int) ($this->redis->get('expired') ?: 0),
            'failures' => (int) ($this->redis->get('upload-failures') ?: 0)];
    }

    public function uploadFailed(): void
    {
        try { $r = $this->connection(); $r->incr('upload-failures'); $r->expire('upload-failures', 604800); } catch (\Throwable $e) {}
    }

    public function acknowledge(array $members, string $token): void
    {
        if (!$members) return;
        $this->redis->eval("if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end for i=2,#ARGV do redis.call('ZREM',KEYS[2],ARGV[i]) end return 1", 2, 'flush-lock', 'pending', $token, ...$members);
    }

    public function unlock(string $token): void
    {
        $this->redis->eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", 1, 'flush-lock', $token);
    }

    public function controlConnection() { return $this->connection(); }
}
