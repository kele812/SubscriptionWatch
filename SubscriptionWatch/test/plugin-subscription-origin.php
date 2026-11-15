<?php
namespace App\Models {
    class User {
        public static array $rows=[];
        public function getTable(){return 'v2_user';}
        public static function query(){return new Query;}
    }
    class Query {
        private string $key;private $value;
        public function where($k,$v){$this->key=$k;$this->value=$v;return $this;}
        public function first($columns){foreach(User::$rows as $user)if((string)$user->{$this->key}===(string)$this->value)return $user;return null;}
    }
}
namespace App\Utils {class Helper {public static function getSubscribeUrl($token){return 'https://default.example.com/s/'.$token.'?flag=clash';}}}
namespace App\Services\Plugin {
    class AbstractPlugin {
        public array $filters=[],$options=[];
        protected function filter($n,$fn){$this->filters[$n]=$fn;}protected function listen($n,$fn){}
        public function getConfig(){return $this->options;}
    }
}
namespace Illuminate\Http\Client {class ConnectionException extends \RuntimeException {}}
namespace Illuminate\Redis {
    class RedisManager {
        public function __construct(...$args){}
        public function connection(){return new class {public function eval(...$args){return \Illuminate\Support\Facades\DB::$busy?0:1;}};}
    }
}
namespace Illuminate\Support\Facades {
    class Log {public static array $entries=[];public static function warning($m,$c=[]){self::$entries[]=$c;}}
    class Schema {
        public static function hasTable($n){return isset(DB::$tables[$n]);}
        public static function create($n,$fn){DB::$tables[$n]=[];$fn(new class {public function __call($n,$args){return $this;}});}
    }
    class DB {
        public static array $tables=[];public static int $reads=0;public static bool $fail=false,$busy=false;
        public static function table($n){return new Builder($n);}
        public static function transaction($fn){$old=self::$tables;try{return $fn();}catch(\Throwable $e){self::$tables=$old;throw $e;}}
    }
    class Builder {
        private array $where=[];private bool $joined=false;
        public function __construct(private string $name){$this->name=explode(' as ',$name)[0];}
        public function where($k,$v){$parts=explode('.',$k);$this->where[end($parts)]=$v;return $this;}
        public function join(...$args){$this->joined=true;return $this;}
        private function matches($r){foreach($this->where as $k=>$v)if(($r[$k]??null)!==$v)return false;return true;}
        private function rows(){if(!isset(DB::$tables[$this->name]))throw new \RuntimeException('Missing table');return array_values(array_filter(DB::$tables[$this->name],fn($r)=>$this->matches($r)));}
        public function get($columns){DB::$reads++;$out=[];foreach($this->rows() as $r){if(!$this->joined){$out[]=(object)$r;continue;}foreach(\App\Models\User::$rows as $u)if($r['uid']===$u->id)$out[]=(object)[...$r,'token'=>$u->token,'current_email'=>$u->email];}return $out;}
        public function value($k){return $this->rows()[0][$k]??null;}
        public function delete(){DB::$tables[$this->name]=array_values(array_filter(DB::$tables[$this->name],fn($r)=>!$this->matches($r)));}
        public function insert($rows){if(DB::$fail)throw new \RuntimeException('Write failure');DB::$tables[$this->name]=array_merge(DB::$tables[$this->name],$rows);}
        public function updateOrInsert($key,$v){foreach(DB::$tables[$this->name] as &$r)if(!array_diff_assoc($key,$r)){$r=array_merge($r,$v);return;}DB::$tables[$this->name][]=array_merge($key,$v);}
    }
    class Http {
        public static string $mode='valid',$secret;public static array $users=[],$last=[];public static int $calls=0;
        public static function connectTimeout($s){return new TestRequest;}
    }
    class TestRequest {
        private array $h;private string $raw;
        public function timeout($s){return $this;}public function withoutRedirecting(){return $this;}
        public function withHeaders($h){$this->h=$h;return $this;}public function withBody($b,$t){$this->raw=$b;return $this;}
        public function post($url){
            Http::$calls++;$e=json_decode($this->raw,true);Http::$last=$e;
            if(!str_ends_with($url,'/subscription-origin-sync')||str_contains($this->raw,'token'))throw new \RuntimeException('Unexpected remote link lookup');
            if(!hash_equals(hash_hmac('sha256',"subscription-origin-sync-request\n".$this->h['X-Watch-Timestamp']."\n".$this->raw,Http::$secret),$this->h['X-Watch-Signature']))throw new \RuntimeException('Bad request signature');
            if(Http::$mode==='unavailable')throw new \Illuminate\Http\Client\ConnectionException('Outage');
            if(Http::$mode==='error')return new TestResponse('{}',403);
            if(Http::$mode==='live'){
                $h=['Content-Type: application/json'];foreach($this->h as $k=>$v)$h[]=$k.': '.$v;
                $raw=file_get_contents(getenv('WATCH_TEST_BASE').'/api/collector/subscription-origin-sync',false,stream_context_create(['http'=>['method'=>'POST','header'=>implode("\r\n",$h),'content'=>$this->raw,'ignore_errors'=>true,'timeout'=>5]]));
                if($raw===false)throw new \RuntimeException('Local server unavailable');return new TestResponse($raw);
            }
            $rev=hash('sha256',json_encode(Http::$users));$unchanged=$e['cursor']===0&&$e['revision']===$rev;
            $rows=$unchanged?[]:array_values(array_filter(Http::$users,fn($u)=>$u['user_id']>$e['cursor']));$next=count($rows)>500?$rows[499]['user_id']:null;
            $d=['schema'=>1,'panel'=>$this->h['X-Watch-Panel'],'nonce'=>$e['nonce'],'expires'=>(int)round(microtime(true)*1000)+30000,'revision'=>$rev,'users'=>array_slice($rows,0,500),'unchanged'=>$unchanged,'restart'=>false,'next'=>$next];
            if(Http::$mode==='wrong-panel')$d['panel']=str_repeat('f',48);if(Http::$mode==='wrong-nonce')$d['nonce']=str_repeat('f',48);
            if(Http::$mode==='expired')$d['expires']=1;if(Http::$mode==='future')$d['expires']+=90000;
            if(Http::$mode==='restart'&&$e['cursor']>0)$d['restart']=true;
            $payload=base64_encode(json_encode($d));$sig=hash_hmac('sha256',"subscription-origin-sync-response\n".$payload,Http::$secret);
            if(Http::$mode==='bad-signature')$sig=str_repeat('0',64);return new TestResponse(json_encode(['payload'=>$payload,'signature'=>$sig]));
        }
    }
    class TestResponse {
        public function __construct(private string $raw,private int $code=200){}
        public function successful(){return $this->code>=200&&$this->code<300;}public function status(){return $this->code;}
        public function body(){return $this->raw;}public function json(){return json_decode($this->raw,true);}
    }
}
namespace {
    class TestAttributes {private array $v=[];public function has($k){return array_key_exists($k,$this->v);}public function get($k){return $this->v[$k]??null;}public function set($k,$v){$this->v[$k]=$v;}}
    class TestWebRequest {
        public TestAttributes $attributes;
        public function __construct(private string $route,private string $body='',private array $headers=[]){$this->attributes=new TestAttributes;}
        public function path(){return $this->route;}public function getContent(){return $this->body;}public function header($k){return $this->headers[$k]??null;}
    }
    class TestHeaders {
        public array $v;public function __construct($type='application/json'){$this->v=['Content-Type'=>$type,'Content-Length'=>'123','ETag'=>'old'];}
        public function get($k){return $this->v[$k]??null;}public function set($k,$v){$this->v[$k]=$v;}public function remove($k){unset($this->v[$k]);}
    }
    class TestJsonResponse {
        public TestHeaders $headers;
        public function __construct(private string $raw,private int $code=200,$type='application/json'){$this->headers=new TestHeaders($type);}
        public function getContent(){return $this->raw;}public function setContent($raw){$this->raw=$raw;}public function getStatusCode(){return $this->code;}
        public function header($k,$v){$this->headers->set($k,$v);return $this;}
    }
    function response(){return new class {public function json($d,$s=200){return new TestJsonResponse(json_encode($d),$s);}};}
    function request(){return $GLOBALS['watchRequest'];}function newRequest($p='api/v1/user/getSubscribe'){$GLOBALS['watchRequest']=new TestWebRequest($p);}
    function app($n=null){static $events;return $events??=new class {public array $callbacks=[];public function listen($e,$fn){$this->callbacks[$e]=$fn;}};}
    function config($key,$default=null){return $key==='database.redis.default'?[]:($default??'test');}
    require __DIR__.'/../../SubscriptionWatchCollector/Plugin.php';
    use App\Models\User;use Illuminate\Support\Facades\DB;use Illuminate\Support\Facades\Http;
    use Plugin\SubscriptionWatchCollector\Services\OriginStore;use Plugin\SubscriptionWatchCollector\Services\SubscriptionOrigin;
    Http::$secret=getenv('WATCH_TEST_SECRET')?:bin2hex(random_bytes(24));$panel=getenv('WATCH_TEST_PANEL')?:str_repeat('a',48);
    $options=['panel_id'=>$panel,'secret'=>Http::$secret,'endpoint'=>'https://watch.example.com'];$token=str_repeat('a',32);$email=getenv('WATCH_TEST_EMAIL')?:'customer@example.com';
    User::$rows[$token]=(object)['id'=>7,'email'=>$email,'token'=>$token];Http::$users=[['user_id'=>7,'email'=>$email,'origin'=>'https://custom.example.com']];
    $service=new SubscriptionOrigin($options);$store=new OriginStore($options);$plugin=new \Plugin\SubscriptionWatchCollector\Plugin;$plugin->options=$options;
    $url='https://default.example.com/s/'.$token.'?flag=clash';newRequest();$sync=new \ReflectionMethod($store,'synchronize');
    if(in_array($argv[1]??'',['live','live-response','notify','lookup'],true)){
        Http::$mode='live';
        if(in_array($argv[1],['notify','lookup'],true)){
            if(getenv('WATCH_TEST_TABLES'))DB::$tables=json_decode(base64_decode(getenv('WATCH_TEST_TABLES')),true);
            $e=json_decode(base64_decode(getenv('WATCH_TEST_NOTIFY')),true);$req=new TestWebRequest('',$e['body'],$e['headers']);
            $r=$store->notify($req,$argv[1]==='lookup');echo json_encode(['status'=>$r->getStatusCode(),'body'=>$r->getContent(),'tables'=>DB::$tables]);exit;
        }
        $sync->invoke($store);$store->poll();newRequest(getenv('WATCH_TEST_ROUTE')?:'api/v2/admin/user/fetch');$plugin->boot();
        if($argv[1]==='live')echo $service->rewrite($url);
        else{$r=new TestJsonResponse(json_encode(['data'=>['rows'=>[['id'=>7,'subscribe_url'=>$url]]]]));SubscriptionOrigin::handled((object)['request'=>request(),'response'=>$r]);echo $r->getContent();}exit;
    }
    $checks=0;function same($a,$e,$label){if($a!==$e)throw new \RuntimeException('Assertion failed: '.$label);$GLOBALS['checks']++;}
    same($service->rewrite($url),$url,'before first sync default');same(Http::$calls,0,'no remote fallback');
    $sync->invoke($store);newRequest();$before=Http::$calls;DB::$reads=0;
    same($service->rewrite($url),str_replace('https://default.example.com','https://custom.example.com',$url),'local override');
    for($i=0;$i<50;$i++)$service->rewrite('https://default.example.com/s/'.sprintf('%032x',$i+100));
    same(DB::$reads,1,'one local read per page');same(Http::$calls,$before,'no network for generated links');
    same($service->rewrite('https://default.example.com/api?token='.$token),'https://custom.example.com/api?token='.$token,'legacy query token');
    same($service->rewrite('https://default.example.com/custom/'.$token.'?token='.str_repeat('b',32)),'https://custom.example.com/custom/'.$token.'?token='.str_repeat('b',32),'path identity first');
    same($service->rewrite(null),null,'nonstring');same($service->rewrite('https://default.example.com/no-token'),'https://default.example.com/no-token','missing token');
    newRequest();same((new SubscriptionOrigin([...$options,'panel_id'=>str_repeat('b',48)]))->rewrite($url),$url,'panel isolation');
    User::$rows[$token]->email='changed@example.com';newRequest();same($service->rewrite($url),$url,'email mismatch');User::$rows[$token]->email=$email;
    User::$rows[$token]->token=str_repeat('b',32);newRequest();same($service->rewrite($url),$url,'token reset');User::$rows[$token]->token=$token;
    foreach(['ftp://unsafe.example','https://user:pass@unsafe.example','https://unsafe.example/path','https://unsafe.example?x=1',"https://unsafe.example\n",'https://unsafe.example\\x'] as $v)same(OriginStore::validOrigin($v),false,'invalid origin');
    $old=DB::$tables;Http::$users[0]['origin']='https://updated.example.com';
    foreach(['unavailable','error','wrong-panel','wrong-nonce','expired','future','bad-signature'] as $mode){Http::$mode=$mode;try{$sync->invoke($store);}catch(\Throwable $e){}same(DB::$tables,$old,'failed sync retains snapshot: '.$mode);}
    Http::$mode='valid';DB::$fail=true;try{$sync->invoke($store);}catch(\Throwable $e){}same(DB::$tables,$old,'transaction rollback');DB::$fail=false;
    $sync->invoke($store);newRequest();same($service->rewrite($url),str_replace('https://default.example.com','https://updated.example.com',$url),'fresh request sees update');
    Http::$users[0]['origin']='http://plain.example.com:8080';$sync->invoke($store);newRequest();
    same($service->rewrite($url),str_replace('https://default.example.com','http://plain.example.com:8080',$url),'HTTP snapshot sync and local rewrite');
    Http::$users=[];$sync->invoke($store);newRequest();same($service->rewrite($url),$url,'deleted override restores default');
    Http::$users=[];for($i=1;$i<=501;$i++)Http::$users[]=['user_id'=>$i,'email'=>'user'.$i.'@example.com','origin'=>'https://page.example.com'];
    $old=DB::$tables;Http::$mode='restart';try{$sync->invoke($store);}catch(\Throwable $e){}same(DB::$tables,$old,'second-page restart no partial write');
    Http::$mode='valid';$sync->invoke($store);same(count(DB::$tables['subscription_watch_origins']),501,'complete paginated snapshot');
    Http::$users=[['user_id'=>7,'email'=>$email,'origin'=>'https://custom.example.com']];$sync->invoke($store);
    $raw=json_encode(['data'=>['rows'=>[['id'=>7,'subscribe_url'=>$url]],'total'=>1],'documentation_url'=>$url]);
    foreach(['api/v2/admin/user/fetch','api/v1/custom-admin/user/fetch','api/v1/user/getSubscribe','api/v2/user/getSubscribe','api/v2/admin/user/getUserInfoById'] as $route){
        newRequest($route);$plugin->boot();$before=Http::$calls;DB::$reads=0;
        same(($plugin->filters['subscribe.url'])($url),str_replace('https://default.example.com','https://custom.example.com',$url),'helper local read');
        $r=new TestJsonResponse($raw);(app('events')->callbacks['Illuminate\\Foundation\\Http\\Events\\RequestHandled'])((object)['request'=>request(),'response'=>$r]);$d=json_decode($r->getContent(),true);
        same($d['data']['rows'][0]['subscribe_url'],str_replace('https://default.example.com','https://custom.example.com',$url),'JSON compatibility');
        same($d['documentation_url'],$url,'unrelated URL');same($d['data']['total'],1,'pagination');same($r->headers->get('Cache-Control'),'private, no-store','no cache');
        same(DB::$reads,1,'helper/fallback share local read');same(Http::$calls,$before,'list has zero HTTP calls');
    }
    foreach([['api/v1/client/subscribe',200,'application/json'],['api/v2/admin/server/fetch',200,'application/json'],['api/v1/user/getSubscribe',403,'application/json'],['api/v1/user/getSubscribe',200,'text/html']] as [$route,$status,$type]){
        newRequest($route);$plugin->boot();$r=new TestJsonResponse($raw,$status,$type);SubscriptionOrigin::handled((object)['request'=>request(),'response'=>$r]);same($r->getContent(),$raw,'exclude unrelated response');
    }
    newRequest('api/v1/user/resetSecurity');$plugin->boot();$r=new TestJsonResponse(json_encode(['data'=>$url]));SubscriptionOrigin::handled((object)['request'=>request(),'response'=>$r]);same(json_decode($r->getContent(),true)['data'],str_replace('https://default.example.com','https://custom.example.com',$url),'reset response local');
    $body=json_encode(['schema'=>1,'nonce'=>str_repeat('c',48)]);$ts=(string)time();$h=['X-Watch-Panel'=>$panel,'X-Watch-Timestamp'=>$ts,'X-Watch-Signature'=>hash_hmac('sha256',"subscription-origin-notify-request\n".$ts."\n".$body,Http::$secret)];
    $before=Http::$calls;$bad=$h;$bad['X-Watch-Signature']=str_repeat('0',64);same($store->notify(new TestWebRequest('',$body,$bad))->getStatusCode(),401,'bad notification denied');same(Http::$calls,$before,'unauthenticated notification no effects');
    DB::$busy=true;same($store->notify(new TestWebRequest('',$body,$h))->getStatusCode(),503,'busy sync pending');DB::$busy=false;
    same($store->notify(new TestWebRequest('',$body,$h))->getStatusCode(),200,'signed notification confirms commit');
    $body=json_encode(['schema'=>1,'nonce'=>str_repeat('c',48),'query'=>'7']);$h['X-Watch-Signature']=hash_hmac('sha256',"subscription-origin-lookup-request\n".$ts."\n".$body,Http::$secret);
    newRequest();$r=$store->notify(new TestWebRequest('',$body,$h),true);$d=json_decode(base64_decode(json_decode($r->getContent(),true)['payload']),true);
    same($d['user']['subscribe_url'],str_replace('https://default.example.com','https://custom.example.com',$url),'explicit lookup current URL');
    same(str_contains(json_encode(\Illuminate\Support\Facades\Log::$entries),$token),false,'no token in diagnostics');
    echo 'SubscriptionOrigin PHP checks passed: '.$checks.PHP_EOL;
}
