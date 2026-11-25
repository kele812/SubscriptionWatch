<?php
require __DIR__ . '/../../SubscriptionWatchCollector/Services/DeviceMetadata.php';
use Plugin\SubscriptionWatchCollector\Services\DeviceMetadata;
$count=0;
function check($value, $name) {if (!$value) throw new RuntimeException($name); $GLOBALS['count']++;}
$secret=str_repeat('k',48);$user=(object)['device_limit'=>3];
$ua='Pa55wall/1.0.30 (Android 16; vivo V2243A)';
$a=DeviceMetadata::capture($user,$ua,'device-0001',$secret);
$b=DeviceMetadata::capture($user,'Clash.Meta/1.19.34 '.$ua,'device-0001',$secret);
check($a['hwid']===$b['hwid'],'Meta format must not count twice');
check($a['device_limit']===3 && $a['platform']==='Android','Signed limit and platform');
$sr='Shadowrocket/2.2.70 (iPhone; iOS 18.0; Scale/3.00)';
$c=DeviceMetadata::capture($user,$sr,'',$secret);
$d=DeviceMetadata::capture($user,$sr,'ignored-id',$secret);
check($c['hwid']===$d['hwid'] && $c['identity_kind']==='ua','iOS Shadowrocket uses original UA even with HWID');
check($c['hwid']!==DeviceMetadata::capture($user,$sr.' changed','',$secret)['hwid'],'Different full UA must count separately');
check(!isset(DeviceMetadata::capture($user,'Pa55wall/1 (Windows)','','k')['hwid']),'Missing HWID is not synthesized from UA');
check(DeviceMetadata::capture((object)['device_limit'=>null],$ua,'device-0001',$secret)['device_limit']===0,'null limit is unlimited');
check(DeviceMetadata::capture((object)['device_limit'=>'2'],$ua,'device-0001',$secret)['device_limit']===2,'Xboard numeric string');
check(!isset(DeviceMetadata::capture((object)['device_limit'=>-1],$ua,'device-0001',$secret)['device_limit']),'Invalid limit is not unlimited');
check($a['hwid']!==DeviceMetadata::capture($user,$ua,'device-0001','other-secret')['hwid'],'Panel-specific device fingerprint');
echo "Device metadata: $count checks passed\n";
