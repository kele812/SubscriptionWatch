<?php
namespace Plugin\SubscriptionWatchCollector\Services {
    class ReviewUnavailable extends \RuntimeException {}
    class Endpoints {
        public static array $posts=[]; public static bool $fail=false;
        public static function parse($v){return [$v];}
        public static function post($urls,$path,$raw,$headers,$budget){
            if(!hash_equals(hash_hmac('sha256',$headers['X-Watch-Timestamp']."\n".$raw,str_repeat('k',48)),$headers['X-Watch-Signature']))throw new \RuntimeException('Signature mismatch');
            self::$posts[]=['path'=>$path,'data'=>json_decode($raw,true),'budget'=>$budget];
            if(self::$fail)throw new ReviewUnavailable('offline');
            return new class(count(json_decode($raw,true)['events'])) {
                public function __construct(private int $count){}
                public function successful(){return true;}
                public function json($key){return ['ok'=>true,'accepted'=>$this->count][$key]??null;}
            };
        }
    }
    class Buffer {
        public static bool $lock=true;public static array $queued=[];public static int $acked=0;
        public function __construct($v){} public function lock($token){return self::$lock;}
        public function batch(){return array_fill(0,100,json_encode(['event_id'=>'old']));}
        public function metrics(){return ['pending'=>100,'dropped'=>0,'expired'=>0];}
        public function acknowledge($members,$token){self::$acked+=count($members);}
        public function unlock($v){} public function uploadFailed(){}
        public function enqueue($event){self::$queued[]=$event;}
    }
}
namespace {
    require __DIR__.'/../../SubscriptionWatchCollector/Services/Collector.php';
    use Plugin\SubscriptionWatchCollector\Services\Collector;
    use Plugin\SubscriptionWatchCollector\Services\Buffer;
    use Plugin\SubscriptionWatchCollector\Services\Endpoints;
    $collector=new Collector(['secret'=>str_repeat('k',48),'endpoint'=>'https://watch.example.invalid','panel_id'=>'test']);
    $event=['event_id'=>'current']; $count=0;
    function check($value,$name){if(!$value)throw new RuntimeException($name);$GLOBALS['count']++;}
    $collector->report($event);
    $post=Endpoints::$posts[0];
    check(count(Endpoints::$posts)===1,'Only one report per request');
    check($post['budget']===1.0,'One-second total timeout');
    check($post['data']['mode']==='request','Explicit request-triggered mode');
    check($post['data']['events'][0]===$event && count($post['data']['events'])===100,'Current event always first; max 99 retries');
    check(Buffer::$acked===99 && count(Buffer::$queued)===0,'Acknowledge only successful old records');
    Buffer::$lock=false; $collector->report($event);
    check(count(Endpoints::$posts[1]['data']['events'])===1,'Another worker cannot delay current result');
    check(!isset(Endpoints::$posts[1]['data']['metrics']),'Do not invent unavailable queue metrics');
    Endpoints::$fail=true;$collector->report($event);
    check(Buffer::$queued===[$event],'Failure retries only on a later subscription request');
    $plugin=file_get_contents(__DIR__.'/../../SubscriptionWatchCollector/Plugin.php');
    check(!str_contains($plugin,'->flush('),'No scheduled subscription reporting');
    echo "Request-triggered report: $count checks passed\n";
}
