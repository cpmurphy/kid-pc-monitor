package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kidpcmonitor/monitor"
	"kidpcmonitor/protocol"
)

const testSecret = "reverse-client-test-secret"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// capture records log lines as "LEVEL message".
type capture struct {
	mu    sync.Mutex
	lines []string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, levelName(r.Level)+" "+r.Message)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }
func (c *capture) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// discoverServer is a panel's HTTP side advertising reversePort.
func discoverServer(t *testing.T, payload any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/discover" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNormalizePanelURL(t *testing.T) {
	for raw, want := range map[string]string{
		"":                            "",
		"  ":                          "",
		"192.168.1.5:5000":            "http://192.168.1.5:5000",
		" https://panel.lan:5000/ \n": "https://panel.lan:5000",
		"http://x//":                  "http://x",
	} {
		if got := NormalizePanelURL(raw); got != want {
			t.Errorf("%q: got %q, want %q", raw, got, want)
		}
	}
}

func TestAdvertisedPort(t *testing.T) {
	for _, tc := range []struct {
		payload map[string]any
		want    int
	}{
		{nil, 9998},
		{map[string]any{}, 9998},
		{map[string]any{"reverse_port": 9000.0}, 9000},
		{map[string]any{"reverse_port": 9000.9}, 9000},
		{map[string]any{"reverse_port": " 9001 "}, 9001},
		{map[string]any{"reverse_port": "nope"}, 9998},
		{map[string]any{"reverse_port": nil}, 9998},
		{map[string]any{"reverse_port": true}, 1},
	} {
		if got := advertisedPort(tc.payload); got != tc.want {
			t.Errorf("%v: got %d, want %d", tc.payload, got, tc.want)
		}
	}
}

func TestSubnetHosts(t *testing.T) {
	hosts := subnetHosts("192.168.7.42")
	if len(hosts) != 254 || hosts[0] != "192.168.7.1" || hosts[253] != "192.168.7.254" {
		t.Fatalf("hosts = %d [%s .. %s]", len(hosts), hosts[0], hosts[len(hosts)-1])
	}
	if subnetHosts("not-an-ip") != nil || subnetHosts("::1") != nil {
		t.Fatal("non-IPv4 produced hosts")
	}
}

func TestDiscoveryOrderAndCache(t *testing.T) {
	panel := discoverServer(t, map[string]any{"service": DiscoveryMarker, "reverse_port": 9998})
	other := discoverServer(t, map[string]any{"service": "something-else"})
	dir := t.TempDir()
	c := &ReverseClient{DataDir: dir, Logger: quiet(), LocalIP: func() string { return "not-an-ip" }}
	ctx := context.Background()

	// Env wins, and a hit is cached.
	t.Setenv(PanelURLEnv, strings.TrimPrefix(panel.URL, "http://")+"/")
	if got := c.discoverPanelURL(ctx); got != panel.URL {
		t.Fatalf("env: got %q, want %q", got, panel.URL)
	}
	if got := readFile(t, filepath.Join(dir, CacheFile)); got != panel.URL+"\n" {
		t.Fatalf("cache = %q", got)
	}

	// A non-panel env URL falls through to the cache.
	t.Setenv(PanelURLEnv, other.URL)
	if got := c.discoverPanelURL(ctx); got != panel.URL {
		t.Fatalf("cache: got %q", got)
	}

	// Nothing answers and there is no subnet to scan.
	os.Remove(filepath.Join(dir, CacheFile))
	if got := c.discoverPanelURL(ctx); got != "" {
		t.Fatalf("got %q, want none", got)
	}
}

func TestDiscoverPayloadRejects(t *testing.T) {
	for _, payload := range []any{
		map[string]any{"service": "other"},
		[]any{"kid-pc-monitor-panel"},
		"kid-pc-monitor-panel",
	} {
		srv := discoverServer(t, payload)
		if discoverPayload(context.Background(), srv.URL) != nil {
			t.Errorf("%v accepted", payload)
		}
	}
	if discoverPayload(context.Background(), "http://127.0.0.1:1") != nil {
		t.Error("closed port accepted")
	}
}

func TestConnectFailureWarnsOnceUntilSuccess(t *testing.T) {
	// A port that refuses connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	panel := discoverServer(t, map[string]any{"service": DiscoveryMarker, "reverse_port": deadPort})

	logs := &capture{}
	c := &ReverseClient{
		DataDir: t.TempDir(), Logger: slog.New(logs),
		LoadSecret: func() (string, error) { return testSecret, nil },
	}
	for i := 0; i < 2; i++ {
		c.panelURL = panel.URL
		if d := c.ConnectOnce(context.Background()); d < reconnectMin || d > reconnectMin+3*time.Second {
			t.Fatalf("delay %v", d)
		}
		if c.panelURL != "" {
			t.Fatal("failed connection kept the panel URL")
		}
	}
	var warnings, debugs int
	for _, l := range logs.all() {
		if strings.Contains(l, "Reverse connect failed") {
			if strings.HasPrefix(l, "WARNING") {
				warnings++
			} else if strings.HasPrefix(l, "DEBUG") {
				debugs++
			}
		}
	}
	if warnings != 1 || debugs != 1 {
		t.Fatalf("warnings=%d debugs=%d: %v", warnings, debugs, logs.all())
	}
}

func TestNoSecretWaits(t *testing.T) {
	logs := &capture{}
	c := &ReverseClient{DataDir: t.TempDir(), Logger: slog.New(logs),
		LoadSecret: func() (string, error) { return "", errors.New("none") }}
	if d := c.ConnectOnce(context.Background()); d != idleRetry {
		t.Fatalf("delay %v", d)
	}
	if got := logs.all(); len(got) != 1 || got[0] != "ERROR No shared secret configured; reverse TCP disabled" {
		t.Fatalf("logs %v", got)
	}
}

// --- end to end ---------------------------------------------------------------

type fakePlatform struct {
	mu       sync.Mutex
	messages []string
}

func (p *fakePlatform) CheckSessionLocked() (bool, error) { return false, nil }
func (p *fakePlatform) SessionIsActive() (bool, error)    { return true, nil }
func (p *fakePlatform) LockWorkstation() error            { return nil }
func (p *fakePlatform) Shutdown(int64) error              { return nil }
func (p *fakePlatform) CancelShutdown() error             { return nil }
func (p *fakePlatform) Hostname() string                  { return "KIDPC" }
func (p *fakePlatform) ShowMessage(message, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.messages = append(p.messages, message)
	return nil
}

// panelSide accepts one agent on ln and runs requests against it.
type panelSide struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func (p *panelSide) do(params protocol.RequestParams) *protocol.Response {
	p.t.Helper()
	params.Secret = testSecret
	body, err := protocol.BuildRequest(params)
	if err != nil {
		p.t.Fatal(err)
	}
	_ = p.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.WriteFrame(p.conn, body); err != nil {
		p.t.Fatal(err)
	}
	reply, err := protocol.ReadFrame(p.br)
	if err != nil {
		p.t.Fatal(err)
	}
	resp, err := protocol.ParseResponse(reply, testSecret, protocol.ResponseOptions{ExpectedName: params.Name}, time.Now().Unix())
	if err != nil {
		p.t.Fatalf("response: %v\n%s", err, reply)
	}
	return resp
}

func runSession(t *testing.T, ln net.Listener, panelURL string, script func(p *panelSide)) {
	t.Helper()
	platform := &fakePlatform{}
	control, err := monitor.New(monitor.Config{
		Platform: platform, CurrentUser: "kid", DataDir: t.TempDir(), Logger: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := &capture{}
	client := &ReverseClient{
		Control: control, DataDir: t.TempDir(), Logger: slog.New(logs),
		LoadSecret: func() (string, error) { return testSecret, nil },
	}
	t.Setenv(PanelURLEnv, panelURL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
	}
	p := &panelSide{t: t, conn: conn, br: bufio.NewReader(conn)}
	script(p)

	resp := p.do(protocol.RequestParams{Action: "message", Name: "KIDPC", Val: "Dinner is ready"})
	if !resp.OK() {
		t.Fatalf("message: %+v", resp)
	}
	platform.mu.Lock()
	got := append([]string(nil), platform.messages...)
	platform.mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "Dinner is ready") {
		t.Fatalf("popups %q", got)
	}

	// The panel hangs up; the agent logs it and goes back to reconnecting.
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !contains(logs.all(), "INFO Panel closed reverse connection") {
		if time.Now().After(deadline) {
			t.Fatalf("no hang-up log: %v", logs.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if !strings.HasPrefix(logs.all()[0], "INFO Connected reverse session to panel 127.0.0.1:") {
		t.Fatalf("logs %v", logs.all())
	}
}

func contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func TestReverseSessionEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	panel := discoverServer(t, map[string]any{"service": DiscoveryMarker, "reverse_port": ln.Addr().(*net.TCPAddr).Port})

	runSession(t, ln, panel.URL, func(p *panelSide) {
		resp := p.do(protocol.RequestParams{Action: "get", Var: "current_user"})
		if !resp.OK() || resp.Result != "kid" || resp.Name == nil || *resp.Name != "KIDPC" {
			t.Fatalf("get: %+v", resp)
		}
		// A request signed with the wrong secret is refused, not served.
		body, _ := protocol.BuildRequest(protocol.RequestParams{Action: "get", Var: "current_user", Secret: "wrong-secret"})
		_ = protocol.WriteFrame(p.conn, body)
		reply, err := protocol.ReadFrame(p.br)
		if err != nil || !strings.Contains(reply, protocol.AuthenticationFailed) {
			t.Fatalf("wrong secret: %v %s", err, reply)
		}
	})
}

// The panel's HTTPS certificate is self-signed: the agent falls back to an
// unverified TLS session, as the Python agent does.
func TestReverseSessionSelfSignedTLS(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler()) // borrow its self-signed cert
	cfg := &tls.Config{Certificates: cert.TLS.Certificates}
	cert.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// The verified attempt is refused by the client; the unverified retry
	// arrives as a second connection.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	conn, err := openReverse(context.Background(), "127.0.0.1", port, true)
	if err != nil {
		t.Fatalf("openReverse: %v", err)
	}
	defer conn.Close()
	if !conn.(*tls.Conn).ConnectionState().HandshakeComplete {
		t.Fatal("no TLS session")
	}
}
