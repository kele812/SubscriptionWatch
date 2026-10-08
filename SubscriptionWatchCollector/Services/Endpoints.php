<?php
namespace Plugin\SubscriptionWatchCollector\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

class ReviewUnavailable extends \RuntimeException {}

class Endpoints
{
    public static function parse(string $value): array
    {
        $items = preg_split('/[\s,]+/u', trim($value), -1, PREG_SPLIT_NO_EMPTY);
        if (!$items || count($items) > 5) throw new \InvalidArgumentException('Provide 1-5 HTTPS origins');
        $urls = [];
        foreach ($items as $item) {
            if (strlen($item) > 255) throw new \InvalidArgumentException('Invalid watch origin');
            $url = parse_url($item);
            if (!is_array($url) || ($url['scheme'] ?? '') !== 'https' || empty($url['host'])
                || isset($url['user']) || isset($url['pass']) || isset($url['query']) || isset($url['fragment'])
                || !in_array($url['path'] ?? '', ['', '/'], true))
                throw new \InvalidArgumentException('Watch origins must be HTTPS roots');
            $origin = rtrim($item, '/');
            if (!in_array($origin, $urls, true)) $urls[] = $origin;
        }
        return $urls;
    }

    public static function post(array $urls, string $path, string $body, array $headers, float $budget)
    {
        $deadline = microtime(true) + $budget;
        foreach ($urls as $index => $url) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0.05) break;
            $slot = $remaining / (count($urls) - $index);
            try {
                $response = Http::connectTimeout(min(1.0, $slot))->timeout($slot)->withoutRedirecting()
                    ->withHeaders($headers)->withBody($body, 'application/json')->post($url . $path);
            } catch (ConnectionException $e) {
                continue;
            }
            if ($response->status() >= 500) continue;
            return $response;
        }
        throw new ReviewUnavailable('All watch origins unavailable');
    }
}
