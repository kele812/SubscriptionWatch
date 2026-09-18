<?php
namespace App\Models {
    class User {
        public static array $rows=[];
        public static int $saves=0;
        public int $id=1,$banned=0,$is_admin=0,$is_staff=0,$balance=42;
        public string $email='sample@example.com';
        public static function query(){return new Query;}
        public function save(){self::$saves++;return true;}
    }
    class Query {
        private int $id;
        public function whereKey($id){$this->id=$id;return $this;}
        public function lockForUpdate(){return $this;}
        public function first(){return User::$rows[$this->id]??null;}
    }
}
namespace App\Services {
    class AuthService {
        public static bool $fail=false; public static int $calls=0;
        public function __construct($user){}
        public function removeAllSessions(){self::$calls++;if(self::$fail)throw new \RuntimeException('test failure');return true;}
    }
}
namespace Illuminate\Support\Facades {
    class DB {
        public static function transaction($fn){$snapshot=unserialize(serialize(\App\Models\User::$rows));try{return $fn();}catch(\Throwable $e){\App\Models\User::$rows=$snapshot;throw $e;}}
    }
    class Http {
        public static string $mode='valid';public static array $tasks=[],$last=[];
        public static function connectTimeout($seconds){return new Request;}
    }
    class Request {
        private array $headers;private string $body;
        public function timeout($s){return $this;}
        public function withoutRedirecting(){return $this;}
        public function withHeaders($h){$this->headers=$h;return $this;}
        public function withBody($b,$type){$this->body=$b;return $this;}
        public function post($url){
            $secret=str_repeat('k',48);$req=json_decode($this->body,true);Http::$last=$req;
            if(!hash_equals(hash_hmac('sha256',"control-request\n".$this->headers['X-Watch-Timestamp']."\n".$this->body,$secret),$this->headers['X-Watch-Signature']))throw new \RuntimeException('bad request signature');
            $data=['schema'=>1,'panel'=>$this->headers['X-Watch-Panel'],'nonce'=>$req['nonce'],'expires'=>(int)round(microtime(true)*1000)+30000,'tasks'=>Http::$tasks,'acknowledged'=>array_column($req['results'],'id')];
            if(Http::$mode==='wrong_nonce')$data['nonce']=str_repeat('f',48);
            if(Http::$mode==='wrong_panel')$data['panel']=str_repeat('f',48);
            if(Http::$mode==='expired_response')$data['expires']=1;
            $payload=base64_encode(json_encode($data));$signature=hash_hmac('sha256',"control-response\n".$payload,$secret);
            if(Http::$mode==='bad_signature')$signature=str_repeat('0',64);
            return new Response(['payload'=>$payload,'signature'=>$signature]);
        }
    }
    class Response {
        public function __construct(private array $data){}
        public function successful(){return true;}
        public function body(){return json_encode($this->data);}
        public function json(){return $this->data;}
    }
}
namespace {
    require __DIR__.'/../../SubscriptionWatchCollector/Services/Control.php';
    use App\Models\User;use App\Services\AuthService;use Illuminate\Support\Facades\Http;
    function check($value,$message){if(!$value)throw new \RuntimeException($message);}
    class RedisStub {
        public array $hash=[],$seen=[];
        public function hgetall($k){return $this->hash[$k]??[];}
        public function hlen($k){return count($this->hash[$k]??[]);}
        public function hdel($k,$id){unset($this->hash[$k][$id]);}
        public function hset($k,$id,$value){$this->hash[$k][$id]=$value;}
        public function eval($script,$n,$seen,$results,$id){if(isset($this->seen[$seen])||$this->hlen($results)>=100)return 0;$this->seen[$seen]=true;$this->hset($results,$id,'failed');return 1;}
    }
    $control=new \Plugin\SubscriptionWatchCollector\Services\Control([]);
    $exchange=new \ReflectionMethod($control,'exchange');
    $task=['id'=>str_repeat('a',48),'action'=>'ban','user_id'=>1,'email'=>'sample@example.com','expires'=>(int)round(microtime(true)*1000)+20000];
    function runCase($mode,$task,$user=null,$failure=false){
        global $control,$exchange;
        User::$rows=$user?[1=>$user]:[];User::$saves=0;AuthService::$calls=0;AuthService::$fail=$failure;Http::$mode=$mode;Http::$tasks=[$task];
        $redis=new RedisStub;
        $exchange->invoke($control,$redis,'test:','https://watch.example.com',str_repeat('b',48),str_repeat('k',48),true);
        return $redis;
    }
    foreach(['bad_signature','wrong_nonce','wrong_panel','expired_response'] as $mode){runCase($mode,$task,new User);check(User::$saves===0,'Untrusted response executed: '.$mode);}
    $redis=runCase('valid',$task,new User);check(User::$rows[1]->banned===1 && User::$rows[1]->balance===42 && AuthService::$calls===1,'Ban must preserve unrelated fields and remove sessions');check($redis->hash['test:results'][$task['id']]==='banned','Result missing');
    // Simulate a duplicate task in a fresh signed response: the executor still must not run twice.
    $exchange->invoke($control,$redis,'test:','https://watch.example.com',str_repeat('b',48),str_repeat('k',48),true);check(User::$saves===1,'Duplicate re-executed');check(count(Http::$last['results'])===1,'Result not retransmitted');
    foreach(['is_admin','is_staff'] as $field){$u=new User;$u->$field=1;$redis=runCase('valid',$task,$u);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='rejected','Privileged user not rejected');}
    $u=new User;$u->email='other@example.com';$redis=runCase('valid',$task,$u);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='rejected','Email mismatch not rejected');
    $redis=runCase('valid',$task);check($redis->hash['test:results'][$task['id']]==='rejected','Missing user not rejected');
    $expired=$task;$expired['expires']=1;$redis=runCase('valid',$expired,new User);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='expired','Expired task executed');
    $u=new User;$u->banned=1;$redis=runCase('valid',$task,$u);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='already_banned','Already banned user modified');
    $redis=runCase('valid',$task,new User,true);check(User::$rows[1]->banned===0 && $redis->hash['test:results'][$task['id']]==='failed','Transaction rollback/result failed');
    $unban=$task;$unban['action']='unban';$u=new User;$u->banned=1;$redis=runCase('valid',$unban,$u);check(User::$rows[1]->banned===0 && User::$rows[1]->balance===42 && AuthService::$calls===0 && $redis->hash['test:results'][$task['id']]==='unbanned','Unban failed or changed unrelated fields');
    $redis=runCase('valid',$unban,new User);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='already_unbanned','Unban not idempotent');
    foreach(['is_admin','is_staff'] as $field){$u=new User;$u->banned=1;$u->$field=1;$redis=runCase('valid',$unban,$u);check(User::$saves===0 && $redis->hash['test:results'][$task['id']]==='rejected','Unban changed privileged account');}
    $invalid=$task;$invalid['action']='delete';runCase('valid',$invalid,new User);check(User::$saves===0,'Other action accepted');
    echo "PASS: PHP signed control responses, replay guard, expiration, user protections, session removal and failure rollback (mock Xboard/Redis/HTTP).\n";
}
