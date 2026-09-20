package singbox

import (
	"context"
	singM "github.com/sagernet/sing/common/metadata"
	"testing"
)

func TestWatchAccessBypassesPanelDiagnostics(t *testing.T) {
	tracker := NewConnTracker(0)
	calls := 0
	tracker.watchRecord = func(uid int, source, network, target string) {
		calls++
		if uid != 7 || source != "1.2.3.4" || network != "tcp" || target != "example.com:443" {
			t.Fatal("wrong target metadata")
		}
	}
	if activity := tracker.recordAccess(7, "1.2.3.4", "tcp", "example.com:443"); activity != nil {
		t.Fatal("created duplicate panel activity")
	}
	if calls != 1 || len(tracker.FlushRecentAccess()) != 0 {
		t.Fatal("diagnostic feed duplicated")
	}
}

func TestWatchAccessKeepsTrafficAndConnectionLifecycle(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	calls := 0
	tracker.watchRecord = func(uid int, source, network, target string) {
		calls++
		if uid != 1 || target != "example.com:443" {
			t.Fatal("wrong connection target")
		}
	}
	metadata := testInboundContext("uuid-1", "1.2.3.4")
	metadata.Destination = singM.ParseSocksaddr("example.com:443")
	conn := tracker.RoutedConnection(context.Background(), &testConn{}, metadata, nil, nil)
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	traffic, _, count := tracker.GetUserTraffic()
	if traffic[1][1] != 3 || count != 1 || calls != 1 {
		t.Fatal("traffic accounting changed")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, count = tracker.GetUserTraffic()
	if count != 0 {
		t.Fatal("connection not released")
	}
	if len(tracker.FlushRecentAccess()) != 0 {
		t.Fatal("destination sent to panel")
	}
}
