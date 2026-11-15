<?php
use Illuminate\Support\Facades\Route;
use Plugin\SubscriptionWatchCollector\Services\OriginStore;

Route::post('/api/v1/guest/subscription-watch/origin-sync', static function (\Illuminate\Http\Request $request) {
    $options = $request->attributes->get('_watch_subscription_origin_options');
    if (!is_array($options)) return response()->json(['error' => 'plugin unavailable'], 503);
    return (new OriginStore($options))->notify($request);
});

Route::post('/api/v1/guest/subscription-watch/origin-lookup', static function (\Illuminate\Http\Request $request) {
    $options = $request->attributes->get('_watch_subscription_origin_options');
    if (!is_array($options)) return response()->json(['error' => 'plugin unavailable'], 503);
    return (new OriginStore($options))->notify($request, true);
});
