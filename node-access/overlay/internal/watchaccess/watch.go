// Package watchaccess sends selected-user destination metadata directly to
// SubscriptionWatch. No network or disk I/O runs on the proxy connection path.
package watchaccess

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Config struct {
	URL    string `yaml:"url"`
	Node   string `yaml:"node"`
	Secret string `yaml:"secret"`
}
type Event struct {
	ID      string `json:"id"`
	UID     int    `json:"uid"`
	Since   int64  `json:"since"`
	TS      int64  `json:"ts"`
	Source  string `json:"source"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}
type policy struct {
	users map[int]int64
	until time.Time
}
type Reporter struct {
	cfg      Config
	client   *http.Client
	queue    chan Event
	policy   atomic.Pointer[policy]
	prefix   string
	seq      atomic.Uint64
	dropped  atomic.Uint64
	failures atomic.Uint64
}

func New(c Config) (*Reporter, error) {
	if c.URL == "" && c.Node == "" && c.Secret == "" {
		return nil, nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(c.Node) != 48 || len(c.Secret) != 48 {
		return nil, fmt.Errorf("watch_access requires HTTPS origin, node and secret (48 hex characters)")
	}
	if _, err = hex.DecodeString(c.Node); err != nil {
		return nil, fmt.Errorf("invalid watch_access node")
	}
	if _, err = hex.DecodeString(c.Secret); err != nil {
		return nil, fmt.Errorf("invalid watch_access secret")
	}
	seed := make([]byte, 16)
	if _, err = rand.Read(seed); err != nil {
		return nil, err
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return &Reporter{cfg: c, prefix: hex.EncodeToString(seed), queue: make(chan Event, 1000), client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Record records a connection target once, not each packet or page request.
// Full queues discard records instead of slowing down the proxy.
func (r *Reporter) Record(uid int, source, network, destination string) {
	p := r.policy.Load()
	now := time.Now()
	if p == nil || now.After(p.until) {
		return
	}
	since, ok := p.users[uid]
	if !ok {
		return
	}
	destination = strings.TrimPrefix(strings.TrimPrefix(destination, "tcp:"), "udp:")
	host, port, err := net.SplitHostPort(destination)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1 || n > 65535 || len(host) > 253 || host == "" || net.ParseIP(source) == nil || (network != "tcp" && network != "udp") {
		r.dropped.Add(1)
		return
	}
	if net.ParseIP(host) == nil {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				r.dropped.Add(1)
				return
			}
		}
	}
	event := Event{ID: r.prefix + "-" + strconv.FormatUint(r.seq.Add(1), 10), UID: uid, Since: since, TS: now.UnixMilli(), Source: source, Host: strings.ToLower(host), Port: n, Network: network}
	select {
	case r.queue <- event:
	default:
		r.dropped.Add(1)
	}
}
func (r *Reporter) request(ctx context.Context, path string, payload any, result any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(r.cfg.Secret))
	mac.Write([]byte(path + "\n" + stamp + "\n"))
	mac.Write(raw)
	req, err := http.NewRequestWithContext(ctx, "POST", r.cfg.URL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Watch-Node", r.cfg.Node)
	req.Header.Set("X-Watch-Timestamp", stamp)
	req.Header.Set("X-Watch-Signature", hex.EncodeToString(mac.Sum(nil)))
	res, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return fmt.Errorf("watch access HTTP %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(result)
}
func (r *Reporter) syncPolicy(ctx context.Context) error {
	var b struct {
		Users []struct {
			UID   int   `json:"uid"`
			Since int64 `json:"since"`
		} `json:"users"`
		TTL int `json:"ttlSeconds"`
	}
	if err := r.request(ctx, "/api/node-access/policy", map[string]int{"schema": 1}, &b); err != nil {
		return err
	}
	if len(b.Users) > 100 || b.TTL < 1 || b.TTL > 90 {
		return fmt.Errorf("invalid watch access policy")
	}
	p := &policy{users: make(map[int]int64), until: time.Now().Add(time.Duration(b.TTL) * time.Second)}
	for _, u := range b.Users {
		if u.UID < 1 || u.Since <= 0 {
			return fmt.Errorf("invalid selected user")
		}
		p.users[u.UID] = u.Since
	}
	r.policy.Store(p)
	return nil
}
func (r *Reporter) send(ctx context.Context, events []Event) error {
	var result struct {
		Inserted   int `json:"inserted"`
		Rejected   int `json:"rejected"`
		Duplicates int `json:"duplicates"`
	}
	err := r.request(ctx, "/api/node-access/events", map[string]any{"schema": 1, "events": events, "metrics": map[string]any{"pending": len(r.queue), "dropped": r.dropped.Load(), "failures": r.failures.Load()}}, &result)
	if err != nil {
		return err
	}
	if result.Inserted < 0 || result.Rejected < 0 || result.Duplicates < 0 || result.Inserted+result.Rejected+result.Duplicates != len(events) {
		return fmt.Errorf("invalid watch access acknowledgement")
	}
	return nil
}

// Run has one upload worker, one in-flight batch, and at most three attempts.
// Policy expires after 90 seconds without a successful refresh (fail closed).
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer r.policy.Store(nil)
	var nextPolicy time.Time
	var batch []Event
	attempts := 0
	for {
		if time.Now().After(nextPolicy) {
			nextPolicy = time.Now().Add(25 * time.Second)
			if err := r.syncPolicy(ctx); err != nil {
				r.failures.Add(1)
				slog.Warn("watch access policy unavailable")
			}
		}
		if batch == nil {
			batch = make([]Event, 0, 100)
			for len(batch) < 100 {
				select {
				case e := <-r.queue:
					batch = append(batch, e)
				default:
					goto drained
				}
			}
		}
	drained:
		now := time.Now()
		p := r.policy.Load()
		filtered := batch[:0]
		for _, e := range batch {
			if p == nil || now.After(p.until) || p.users[e.UID] != e.Since || now.UnixMilli()-e.TS > 600000 {
				r.dropped.Add(1)
			} else {
				filtered = append(filtered, e)
			}
		}
		batch = filtered
		if err := r.send(ctx, batch); err != nil {
			r.failures.Add(1)
			attempts++
			if attempts >= 3 {
				r.dropped.Add(uint64(len(batch)))
				batch = nil
				attempts = 0
			}
		} else {
			batch = nil
			attempts = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
