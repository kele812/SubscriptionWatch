<?php
namespace Plugin\SubscriptionWatchCollector;

use App\Services\Plugin\AbstractPlugin;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Plugin\SubscriptionWatchCollector\Services\Collector;

require_once __DIR__ . '/Services/Collector.php';
require_once __DIR__ . '/Services/Buffer.php';
require_once __DIR__ . '/Services/Control.php';

class Plugin extends AbstractPlugin
{
    private static ?\WeakMap $dispatchers = null;

    public function boot(): void
    {
        // Store all request-specific state on the Request, never in an Octane singleton.
        $this->listen('client.subscribe.before', function () {
            $collector = new Collector($this->getConfig());
            try {
                $collector->mark(request());
                $decision = $collector->review(request());
            } catch (\UnexpectedValueException $e) {
                $decision = ['allow' => false, 'redirect' => null];
            } catch (\Throwable $e) {
                // Never deliver a subscription when risk review is unavailable.
                $decision = ['allow' => false, 'redirect' => null];
            }
            if (!$decision['allow']) {
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
            $dispatcher->listen(RequestHandled::class, static function ($event) { Collector::handled($event); });
            self::$dispatchers[$dispatcher] = true;
        }
    }

    public function schedule(Schedule $schedule): void
    {
        $options = $this->getConfig();
        // No Laravel queue jobs or cache locks: those can fall back to SQL on some installs.
        $schedule->call(function () use ($options) {
            try { (new Collector($options))->flush(); } catch (\Throwable $e) {}
            try { (new \Plugin\SubscriptionWatchCollector\Services\Control($options))->poll(); } catch (\Throwable $e) {}
        })->everyMinute()->name('subscription-watch-collector');
    }
}
