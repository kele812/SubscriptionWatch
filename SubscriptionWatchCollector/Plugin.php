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
            try {
                $collector = new Collector($this->getConfig());
                $collector->mark(request());
            } catch (\Throwable $e) {
                // Monitoring must never change a subscription response.
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
