<?php
namespace Plugin\SubscriptionWatchCollector\Services;

final class DeviceMetadata
{
    public static function capture($user, string $ua, string $hwid, string $secret): array
    {
        $meta = [];
        $limit = $user->device_limit ?? null;
        if ($limit === null) $meta['device_limit'] = 0;
        elseif ((is_int($limit) && $limit >= 0) || (is_string($limit) && preg_match('/^\d{1,9}$/D', $limit)))
            $meta['device_limit'] = (int) $limit;
        // iOS Shadowrocket is intentionally counted by the complete original UA.
        // Do not strip version/system fields or merge it with the IP address.
        $iosRocket = stripos($ua, 'Shadowrocket/') !== false && preg_match('/iPhone|iPad|iOS/i', $ua);
        if ($iosRocket) {
            $meta['hwid'] = hash_hmac('sha256', "ua\n" . $ua, $secret);
            $meta['identity_kind'] = 'ua';
            $meta['platform'] = 'iOS';
        } else {
            $meta['identity_kind'] = 'hwid';
            if (strlen($hwid) >= 8 && strlen($hwid) <= 256 && preg_match('/^[\x21-\x7e]+$/D', $hwid))
                $meta['hwid'] = hash_hmac('sha256', "hwid\n" . $hwid, $secret);
            $meta['platform'] = stripos($ua, 'Android') !== false ? 'Android'
                : (stripos($ua, 'Windows') !== false ? 'Windows'
                : (preg_match('/macOS|Mac OS|Macintosh/i', $ua) ? 'macOS' : '未知'));
        }
        return $meta;
    }
}
