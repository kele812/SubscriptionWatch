<?php
namespace Illuminate\Http\Client { class ConnectionException extends \RuntimeException {} }
namespace Illuminate\Support\Facades {
    class Http {
        public static array $last=[];public static string $secret;
        public static function connectTimeout($n){return new GrantHttp;}
    }
    class GrantHttp {
        private array $headers; private string $raw;
        public function timeout($n){return $this;}public function withoutRedirecting(){return $this;}
        public function withHeaders($h){$this->headers=$h;return $this;}public function withBody($b,$t){$this->raw=$b;return $this;}
        public function post($url){
            Http::$last=json_decode($this->raw,true);
            if(!hash_equals(hash_hmac('sha256',$this->headers['X-Watch-Timestamp']."\n".$this->raw,Http::$secret),$this->headers['X-Watch-Signature']))throw new \RuntimeException('Bad request signature');
            if(getenv('WATCH_TEST_BASE')){
                $headers=['Content-Type: application/json'];foreach($this->headers as $k=>$v)$headers[]=$k.': '.$v;
                $raw=file_get_contents(getenv('WATCH_TEST_BASE').'/api/collector/review',false,stream_context_create(['http'=>['method'=>'POST','header'=>implode("\r\n",$headers),'content'=>$this->raw,'ignore_errors'=>true,'timeout'=>5]]));
                $signature='';$status=0;foreach((function_exists('http_get_last_response_headers')?http_get_last_response_headers():(get_defined_vars()['http_response_header']??[])) as $h){if(preg_match('/^HTTP\/\S+ (\d+)/',$h,$m))$status=(int)$m[1];if(stripos($h,'X-Watch-Decision-Signature:')===0)$signature=trim(substr($h,27));}
                return new GrantResponse($raw,$status,$signature);
            }
            $raw=json_encode(['event_id'=>Http::$last['event_id'],'allow'=>true,'redirect'=>null]);
            return new GrantResponse($raw,200,hash_hmac('sha256',$raw,Http::$secret));
        }
    }
    class GrantResponse {
        public function __construct(private string $raw,private int $code,private string $signature){}
        public function status(){return $this->code;}public function body(){return $this->raw;}
        public function json(){return json_decode($this->raw,true);}public function header($name){return $this->signature;}
    }
}
namespace Plugin\SubscriptionWatchCollector\Services {
    class Buffer {public static array $events=[];public function __construct($options){}public function enqueue($event){self::$events[]=$event;}}
}
namespace {
    if(!function_exists('mb_strcut')){function mb_strcut($value,$start,$length,$encoding){return substr($value,$start,$length);}}
    class GrantAttributes {
        private array $data=[];public function has($k){return array_key_exists($k,$this->data);}public function get($k){return $this->data[$k]??null;}
        public function set($k,$v){$this->data[$k]=$v;}public function remove($k){unset($this->data[$k]);}
    }
    class GrantRequest {
        public GrantAttributes $attributes;
        public function __construct(private array $query){$this->attributes=new GrantAttributes;}
        public function user(){return (object)['id'=>7,'email'=>'customer@example.com','token'=>str_repeat('a',32)];}
        public function input($k){return $this->query[$k]??null;}public function server($k,$default){return '8.8.8.8';}
        public function header($k,$default){return $k==='User-Agent'?'blocked-client':$default;}
    }
    require __DIR__.'/../../SubscriptionWatchCollector/Services/Endpoints.php';
    require __DIR__.'/../../SubscriptionWatchCollector/Services/Collector.php';
    use Plugin\SubscriptionWatchCollector\Services\Collector;use Illuminate\Support\Facades\Http;
    Http::$secret=getenv('WATCH_TEST_SECRET')?:str_repeat('k',48);
    $options=['panel_id'=>getenv('WATCH_TEST_PANEL')?:str_repeat('b',48),'secret'=>Http::$secret,'endpoint'=>'https://watch.example.com'];
    if(getenv('WATCH_TEST_BASE')){
        $grant=getenv('WATCH_TEST_GRANT');$request=new GrantRequest($grant?['watch_import'=>$grant]:[]);
        $collector=new Collector($options);$collector->mark($request);echo json_encode($collector->review($request));exit;
    }
    $count=0;function check($condition,$label){if(!$condition)throw new \RuntimeException($label);$GLOBALS['count']++;}
    $grant=str_repeat('c',64);
    foreach([['watch_import'=>$grant],['watch_import'=>['invalid']],['watch_import'=>'1'],['import_fingerprint'=>hash('sha256',$grant)],[]] as $query){
        $request=new GrantRequest($query);$collector=new Collector($options);$collector->mark($request);$collector->review($request);
        if(($query['watch_import']??null)===$grant)check((Http::$last['import_fingerprint']??null)===hash('sha256',$grant),'Missing bound fingerprint');
        else check(!array_key_exists('import_fingerprint',Http::$last),'Untrusted or malformed query claimed exemption');
        check(!str_contains(json_encode(Http::$last),$grant),'Raw grant in review body');
        $response=new class {public $headers;public function __construct(){$this->headers=new class {public function get($key){return $key==='Content-Length'?'100':'text/plain';}};}public function getStatusCode(){return 200;}};
        Collector::handled((object)['request'=>$request,'response'=>$response]);
        $event=\Plugin\SubscriptionWatchCollector\Services\Buffer::$events[array_key_last(\Plugin\SubscriptionWatchCollector\Services\Buffer::$events)];
        check(!str_contains(json_encode($event),$grant)&&!isset($event['import_fingerprint']),'Grant persisted in queue');
    }
    echo 'Collector import grant checks passed: '.$count.PHP_EOL;
}
