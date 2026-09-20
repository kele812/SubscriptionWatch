package xray

import (
	xnet "github.com/xtls/xray-core/common/net"
	"testing"
)

func TestWatchAccessBypassesPanelDiagnostics(t *testing.T) {
	d := &LimitDispatcher{emailToUID: map[string]int{"test": 7}}
	calls := 0
	d.watchRecord = func(uid int, source, network, target string) {
		calls++
		if uid != 7 || source != "1.2.3.4" || network != "tcp" || target != "tcp:example.com:443" {
			t.Fatalf("wrong metadata %d %s %s %s", uid, source, network, target)
		}
	}
	if a := d.recordAccess("test", "1.2.3.4", xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)); a != nil {
		t.Fatal("created duplicate panel activity")
	}
	if calls != 1 || len(d.FlushRecentAccess()) != 0 {
		t.Fatal("diagnostic feed duplicated")
	}
}
