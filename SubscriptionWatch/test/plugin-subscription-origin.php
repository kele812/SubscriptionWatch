<?php
namespace App\Models {
    class User {
        public static array $rows = [];
        public static function query() { return new Query(); }
    }
    class Query {
        private string $token;
        public function where($key, $value) {
            if ($key !== 'token') throw new \RuntimeException('Wrong owner lookup');
            $this->token = $value; return $this;
        }
        public function first($columns) { return User::$rows[$this->token] ?? null; }
    }
}
namespace Illuminate\Http\Client { class ConnectionException extends \RuntimeException {} }
namespace App\Services\Plugin {
    class AbstractPlugin {
        public array $filters = [], $options = [];
        protected function filter($name, $callback) { $this->filters[$name] = $callback; }
        protected function listen($name, $callback) {}
        public function getConfig() { return $this->options; }
    }
}
namespace Illuminate\Support\Facades {
    class Http {
        public static string $mode = 'valid';
        public static ?string $origin = 'https://custom.example.com';
        public static string $secret;
        public static int $calls = 0;
        public static array $last = [];
        public static function connectTimeout($seconds) { return new TestRequest(); }
    }
    class TestRequest {
        private array $headers;
        private string $body;
        public function timeout($seconds) { return $this; }
        public function withoutRedirecting() { return $this; }
        public function withHeaders($headers) { $this->headers = $headers; return $this; }
        public function withBody($body, $type) { $this->body = $body; return $this; }
        public function post($url) {
            Http::$calls++;
            $request = json_decode($this->body, true, 16, JSON_THROW_ON_ERROR);
            Http::$last = $request;
            if (isset($request['token']) || count($request) !== 4) throw new \RuntimeException('Token must stay local');
            $expected = hash_hmac('sha256', "subscription-origin-request\n" . $this->headers['X-Watch-Timestamp'] . "\n" . $this->body, Http::$secret);
            if ($expected !== $this->headers['X-Watch-Signature']) throw new \RuntimeException('Request signature mismatch');
            if (Http::$mode === 'unavailable') throw new \Illuminate\Http\Client\ConnectionException('test outage');
            if (Http::$mode === 'error') return new TestResponse('{}', 403);
            if (Http::$mode === 'live') {
                $headers = ['Content-Type: application/json'];
                foreach ($this->headers as $key => $value) $headers[] = $key . ': ' . $value;
                $body = file_get_contents(getenv('WATCH_TEST_BASE') . '/api/collector/subscription-origin', false,
                    stream_context_create(['http' => ['method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $this->body, 'ignore_errors' => true, 'timeout' => 3]]));
                if ($body === false) throw new \RuntimeException('Local integration server unavailable');
                return new TestResponse($body);
            }
            $data = ['schema' => 1, 'panel' => $this->headers['X-Watch-Panel'], 'nonce' => $request['nonce'],
                'user_id' => $request['user_id'], 'email' => $request['email'], 'origin' => Http::$origin,
                'expires' => (int) round(microtime(true) * 1000) + 30000];
            if (Http::$mode === 'wrong-panel') $data['panel'] = str_repeat('f', 48);
            if (Http::$mode === 'wrong-user') $data['user_id']++;
            if (Http::$mode === 'wrong-email') $data['email'] = 'other@example.com';
            if (Http::$mode === 'wrong-nonce') $data['nonce'] = str_repeat('f', 48);
            if (Http::$mode === 'expired') $data['expires'] -= 60000;
            if (Http::$mode === 'future') $data['expires'] += 90000;
            $payload = base64_encode(json_encode($data, JSON_THROW_ON_ERROR));
            $signature = hash_hmac('sha256', "subscription-origin-response\n" . $payload, Http::$secret);
            if (Http::$mode === 'bad-signature') $signature = str_repeat('0', 64);
            return new TestResponse(json_encode(['payload' => $payload, 'signature' => $signature], JSON_THROW_ON_ERROR));
        }
    }
    class TestResponse {
        public function __construct(private string $raw, private int $code = 200) {}
        public function successful() { return $this->code >= 200 && $this->code < 300; }
        public function body() { return $this->raw; }
        public function json() { return json_decode($this->raw, true); }
        public function status() { return $this->code; }
    }
}
namespace {
    class TestAttributes {
        private array $values = [];
        public function has($key) { return array_key_exists($key, $this->values); }
        public function get($key) { return $this->values[$key]; }
        public function set($key, $value) { $this->values[$key] = $value; }
    }
    function newRequest() { $GLOBALS['watchRequest'] = (object) ['attributes' => new TestAttributes()]; }
    function request() { return $GLOBALS['watchRequest']; }
    function app($name) {
        static $events;
        return $events ??= new class { public function listen($event, $callback) {} };
    }
    require __DIR__ . '/../../SubscriptionWatchCollector/Services/Endpoints.php';
    require __DIR__ . '/../../SubscriptionWatchCollector/Services/SubscriptionOrigin.php';
    require __DIR__ . '/../../SubscriptionWatchCollector/Plugin.php';
    use App\Models\User;
    use Illuminate\Support\Facades\Http;
    use Plugin\SubscriptionWatchCollector\Services\SubscriptionOrigin;
    Http::$secret = getenv('WATCH_TEST_SECRET') ?: bin2hex(random_bytes(24));
    $panel = getenv('WATCH_TEST_PANEL') ?: str_repeat('a', 48);
    $options = ['panel_id' => $panel, 'secret' => Http::$secret, 'endpoint' => 'https://watch.example.com'];
    $token = str_repeat('a', 32);
    User::$rows[$token] = (object) ['id' => 7, 'email' => getenv('WATCH_TEST_EMAIL') ?: 'customer@example.com'];
    User::$rows[str_repeat('b', 32)] = (object) ['id' => 8, 'email' => 'other@example.com'];
    $url = 'https://default.example.com/api/v1/client/subscribe?token=' . $token . '&flag=clash';
    $service = new SubscriptionOrigin($options);
    newRequest();
    if (($argv[1] ?? '') === 'live') {
        Http::$mode = 'live';
        echo $service->rewrite($url);
        exit;
    }
    $checks = 0;
    function same($actual, $expected, $label) {
        if ($actual !== $expected) throw new \RuntimeException('Assertion failed: ' . $label);
        $GLOBALS['checks']++;
    }
    same($service->rewrite($url), str_replace('https://default.example.com', Http::$origin, $url), 'preserve path token and flags');
    same(Http::$last['user_id'], 7, 'owner identity');
    same(array_key_exists('token', Http::$last), false, 'no token upload');
    $service->rewrite($url);
    same(Http::$calls, 1, 'cache only in same request');
    $service->rewrite(str_replace($token, str_repeat('b', 32), $url));
    same(Http::$last['user_id'], 8, 'different customer in same worker');
    newRequest(); Http::$origin = 'https://updated.example.com';
    same($service->rewrite($url), str_replace('https://default.example.com', Http::$origin, $url), 'fresh request sees edit');
    newRequest(); Http::$origin = null;
    same($service->rewrite($url), $url, 'restore default without stale cache');
    foreach (['http://unsafe.example.com', 'https://user:pass@unsafe.example.com', 'https://unsafe.example.com/path', 'https://unsafe.example.com?x=1', "https://unsafe.example.com\n", 'https://unsafe.example.com\\path'] as $unsafe) {
        newRequest(); Http::$origin = $unsafe;
        same($service->rewrite($url), $url, 'reject unsafe origin');
    }
    Http::$origin = 'https://custom.example.com';
    foreach (['unavailable', 'error', 'wrong-panel', 'wrong-user', 'wrong-email', 'wrong-nonce', 'expired', 'future', 'bad-signature'] as $mode) {
        newRequest(); Http::$mode = $mode;
        same($service->rewrite($url), $url, 'reject ' . $mode);
    }
    newRequest(); Http::$mode = 'valid';
    same($service->rewrite(str_replace($token, str_repeat('c', 32), $url)), str_replace($token, str_repeat('c', 32), $url), 'unknown token remains unchanged');
    same($service->rewrite('https://default.example.com/no-token'), 'https://default.example.com/no-token', 'no token');
    same($service->rewrite(null), null, 'nonstring filter value');
    newRequest();
    $otherPanel = new SubscriptionOrigin([...$options, 'panel_id' => str_repeat('b', 48)]);
    $service->rewrite($url); $otherPanel->rewrite($url);
    same(Http::$calls > 1, true, 'panel-scoped request cache');
    newRequest();
    $plugin = new \Plugin\SubscriptionWatchCollector\Plugin();
    $plugin->options = $options;
    $plugin->boot();
    same(isset($plugin->filters['subscribe.url']), true, 'official Xboard filter registered');
    same(($plugin->filters['subscribe.url'])($url), str_replace('https://default.example.com', Http::$origin, $url), 'registered filter rewrites customer link');
    echo 'SubscriptionOrigin PHP checks passed: ' . $checks . PHP_EOL;
}
