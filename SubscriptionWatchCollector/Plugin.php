<?php
namespace Plugin\SubscriptionWatchCollector;

use App\Services\Plugin\AbstractPlugin;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Support\Facades\Log;
use Plugin\SubscriptionWatchCollector\Services\Collector;
use Plugin\SubscriptionWatchCollector\Services\ReviewUnavailable;

require_once __DIR__ . '/Services/Collector.php';
require_once __DIR__ . '/Services/Endpoints.php';
require_once __DIR__ . '/Services/Buffer.php';
require_once __DIR__ . '/Services/Control.php';
require_once __DIR__ . '/Services/SubscriptionOrigin.php';
require_once __DIR__ . '/Services/OriginStore.php';

class Plugin extends AbstractPlugin
{
    private static ?\WeakMap $dispatchers = null;

    public function boot(): void
    {
        \Plugin\SubscriptionWatchCollector\Services\SubscriptionOrigin::mark(request(), $this->getConfig());
        $this->filter('subscribe.url', function ($url) {
            return (new \Plugin\SubscriptionWatchCollector\Services\SubscriptionOrigin($this->getConfig()))->rewrite($url);
        });
        // Store all request-specific state on the Request, never in an Octane singleton.
        $this->listen('client.subscribe.before', function () {
            $options = $this->getConfig();
            $collector = new Collector($options);
            try {
                $collector->mark(request());
                $decision = $collector->review(request());
            } catch (ReviewUnavailable $e) {
                // Only transport errors, timeouts and exhausted 5xx failover may use this option.
                if (filter_var($options['fail_open'] ?? false, FILTER_VALIDATE_BOOLEAN)) return;
                $collector->markFailure(request(), 'review-unavailable');
                $decision = ['allow' => false, 'redirect' => null];
            } catch (\UnexpectedValueException $e) {
                $collector->markFailure(request(), 'review-invalid');
                static $lastWarningAt = 0;
                if (time() - $lastWarningAt >= 60) {
                    $lastWarningAt = time();
                    Log::warning('Subscription Watch review authentication or signature invalid; subscription denied');
                }
                $decision = ['allow' => false, 'redirect' => null];
            } catch (\Throwable $e) {
                // Never deliver a subscription when risk review is unavailable.
                $collector->markFailure(request(), 'review-error');
                $decision = ['allow' => false, 'redirect' => null];
            }
            if (!$decision['allow']) {
                if (isset($decision['device_error'])) {
                    $code = $decision['device_error'];
                    $messages = [
                        'device-limit' => '设备数量已达套餐上限，请等待旧设备名额到期或联系管理员清除设备',
                        'device-id-required' => '请使用发送 X-HWID 设备标识的客户端',
                        'device-metadata' => '无法读取设备上限，请联系管理员检查采集插件',
                    ];
                    $this->intercept(response(json_encode(['message' => $messages[$code]], JSON_UNESCAPED_UNICODE), 403, [
                        'Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store',
                        'X-Pa55wall-Error' => $code,
                    ]));
                    return;
                }
                if ($decision['redirect'])
                    $this->intercept(response('', 302, [
                        'Location' => $decision['redirect'],
                        'Cache-Control' => 'no-store',
                    ]));
                $this->intercept(response('', 403, ['Content-Type' => 'text/plain']));
            }
        });
        $dispatcher = app('events');
        self::$dispatchers ??= new \WeakMap();
        if (!isset(self::$dispatchers[$dispatcher])) {
            $dispatcher->listen(RequestHandled::class, static function ($event) {
                \Plugin\SubscriptionWatchCollector\Services\SubscriptionOrigin::handled($event);
                Collector::handled($event);
            });
            self::$dispatchers[$dispatcher] = true;
        }
    }

    public function schedule(Schedule $schedule): void
    {
        $options = $this->getConfig();
        // No Laravel queue jobs or cache locks: those can fall back to SQL on some installs.
        $schedule->call(function () use ($options) {
            try { (new \Plugin\SubscriptionWatchCollector\Services\OriginStore($options))->poll(); } catch (\Throwable $e) {}
            try { (new \Plugin\SubscriptionWatchCollector\Services\Control($options))->poll(); } catch (\Throwable $e) {}
        })->everyMinute()->name('subscription-watch-collector');
    }
}
