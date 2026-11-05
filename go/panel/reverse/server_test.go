package reverse

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"kidpcmonitor/protocol"
)

const secret = "test-shared-secret"

// fakeAgent answers panel requests like an agent: settings for "get",
// "ok" for actions, a logs block for get_logs (unless noLogs), and records
// every request it sees.
type fakeAgent struct {
	t        *testing.T
	hostname string
	secret   string
	conn     net.Conn

	mu       sync.Mutex
	requests []*protocol.Request
	status   string
	noLogs   bool
	stall    chan struct{} // when set, the agent stops answering until closed
	answered chan string   // action of every answered request
}

func dialAgent(t *testing.T, addr, hostname string) *fakeAgent {
	t.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{t: t, hostname: hostname, secret: secret, conn: conn, status: "UNLOCKED",
		answered: make(chan string, 100)}
	go a.serve()
	t.Cleanup(func() { conn.Close() })
	return a
}

func (a *fakeAgent) serve() {
	r := bufio.NewReader(a.conn)
	for {
		body, err := protocol.ReadFrame(r)
		if err != nil {
			return
		}
		a.mu.Lock()
		stall := a.stall
		a.mu.Unlock()
		if stall != nil {
			<-stall
		}
		reply := protocol.HandleRequest(body, a.secret, a.hostname, time.Now().Unix(), a.dispatch)
		if err := protocol.WriteFrame(a.conn, reply); err != nil {
			return
		}
	}
}

func (a *fakeAgent) dispatch(req *protocol.Request) ([]protocol.Node, error) {
	a.mu.Lock()
	a.requests = append(a.requests, req)
	status, noLogs := a.status, a.noLogs
	a.mu.Unlock()
	defer func() {
		select {
		case a.answered <- req.Action:
		default:
		}
	}()
	switch req.Action {
	case "get":
		return protocol.BlockContent(protocol.Block("settings",
			protocol.N("name", a.hostname),
			protocol.N("status", status),
			protocol.N("daily_limit", int64(120)),
			protocol.N("time_remaining", int64(42)),
		)), nil
	case "get_logs":
		if noLogs {
			return nil, &protocol.ProtocolError{Code: protocol.UnknownAction, Message: "unknown action: get_logs"}
		}
		return protocol.BlockContent(protocol.Block("logs",
			protocol.N("path", `C:\x\pc_control.log`),
			protocol.N("truncated", true),
			protocol.N("lines", "one", "two"),
		)), nil
	case "set":
		if req.Var != nil && *req.Var == "bed_time" && req.Val == "25:00" {
			return nil, &protocol.ProtocolError{Code: protocol.InvalidValue, Message: "bed_time must be HH:MM"}
		}
	}
	return protocol.OKContent("done " + req.Action), nil
}

func (a *fakeAgent) lastRequest() *protocol.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests[len(a.requests)-1]
}

type events struct {
	mu          sync.Mutex
	status      []string // hostname@ip
	disconnects []string
	statusCh    chan string
	disconnCh   chan string
}

func newServer(t *testing.T, configure ...func(*Server)) (*Server, string, *events) {
	t.Helper()
	ev := &events{statusCh: make(chan string, 100), disconnCh: make(chan string, 100)}
	s := &Server{
		Secret: func() (string, error) { return secret, nil },
		OnStatus: func(h, ip string, settings map[string]any) {
			ev.mu.Lock()
			ev.status = append(ev.status, h+"@"+ip)
			ev.mu.Unlock()
			select {
			case ev.statusCh <- h:
			default:
			}
		},
		OnDisconnect: func(h, ip string) {
			ev.mu.Lock()
			ev.disconnects = append(ev.disconnects, h+"@"+ip)
			ev.mu.Unlock()
			select {
			case ev.disconnCh <- h:
			default:
			}
		},
		// The panel notices a vanished agent at its next exchange, so keep
		// the idle refresh short (5 s in production).
		StatusRefresh:   50 * time.Millisecond,
		ExchangeTimeout: 2 * time.Second,
	}
	for _, c := range configure {
		c(s)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return s, ln.Addr().String(), ev
}

func wait(t *testing.T, ch chan string, what string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return ""
	}
}

func waitSession(t *testing.T, s *Server, hostname string) *Session {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sess := s.SessionForHostname(hostname); sess != nil {
			return sess
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no session for %s", hostname)
	return nil
}

func TestIdentifyActionsAndLogs(t *testing.T) {
	s, addr, ev := newServer(t)
	agent := dialAgent(t, addr, "KidPC")
	if got := wait(t, ev.statusCh, "status"); got != "KidPC" {
		t.Fatalf("status from %q", got)
	}
	sess := waitSession(t, s, "KidPC")
	if sess.PeerIP != "127.0.0.1" || s.SessionForIP("127.0.0.1") != sess {
		t.Fatalf("session peer %q", sess.PeerIP)
	}
	if got := sess.Settings()["daily_limit"]; got != int64(120) {
		t.Fatalf("settings daily_limit = %#v", got)
	}
	first := agent.lastRequest()
	if first.Action != "get" || first.Name != nil {
		t.Fatalf("identify request = %+v, want an unnamed get", first)
	}

	ok, text, found := s.PerformAction("127.0.0.1", "set_daily_limit", map[string]any{"minutes": "90"})
	if !found || !ok || text != "done set" {
		t.Fatalf("set_daily_limit = %v %q %v", ok, text, found)
	}
	req := agent.lastRequest()
	if req.Name == nil || *req.Name != "KidPC" || *req.Var != "daily_limit" || req.Val != int64(90) {
		t.Fatalf("set request = %+v", req)
	}

	ok, text, _ = s.PerformAction("127.0.0.1", "message", map[string]any{"message": 2.0})
	if !ok || agent.lastRequest().Val != "2.0" {
		t.Fatalf("float message sent as %#v (%v %q)", agent.lastRequest().Val, ok, text)
	}

	ok, text, _ = s.PerformAction("127.0.0.1", "set_bed_time", map[string]any{"time": "25:00"})
	if ok || text != "invalid_value: bed_time must be HH:MM" {
		t.Fatalf("agent error = %v %q", ok, text)
	}
	ok, text, _ = s.PerformAction("127.0.0.1", "extend_time", map[string]any{"minutes": "abc"})
	if ok || text != "Invalid value for extend_time: invalid literal for int() with base 10: 'abc'" {
		t.Fatalf("invalid value = %v %q", ok, text)
	}
	ok, text, _ = s.PerformAction("127.0.0.1", "message", map[string]any{"message": []any{1}})
	if ok || !strings.HasPrefix(text, "Invalid value for message:") {
		t.Fatalf("unsendable value = %v %q", ok, text)
	}
	ok, text, _ = s.PerformAction("127.0.0.1", "bogus", nil)
	if ok || text != "Invalid value for bogus: 'bogus'" {
		t.Fatalf("unknown action = %v %q", ok, text)
	}
	if _, _, found := s.PerformAction("10.9.9.9", "lock", nil); found {
		t.Fatal("action on an unknown IP found a session")
	}

	logs, err := s.GetLogs("127.0.0.1", 50)
	if err != nil || !logs.Truncated || strings.Join(logs.Lines, ",") != "one,two" {
		t.Fatalf("logs = %+v, %v", logs, err)
	}
	if tail := agent.lastRequest().Tail; tail == nil || *tail != 50 {
		t.Fatalf("tail = %v", tail)
	}
	agent.mu.Lock()
	agent.noLogs = true
	agent.mu.Unlock()
	if _, err := s.GetLogs("127.0.0.1", 50); err == nil || err.Error() != "unknown_action: unknown action: get_logs" {
		t.Fatalf("logs from an old agent: %v", err)
	}
	if _, err := s.GetLogs("10.9.9.9", 50); err == nil {
		t.Fatal("logs for an unknown IP")
	}

	agent.conn.Close()
	if got := wait(t, ev.disconnCh, "disconnect"); got != "KidPC" {
		t.Fatalf("disconnect for %q", got)
	}
	if s.SessionForIP("127.0.0.1") != nil || s.SessionForHostname("KidPC") != nil {
		t.Fatal("session still registered after disconnect")
	}
}

func TestStatusRefreshWhenIdle(t *testing.T) {
	s, addr, ev := newServer(t, func(s *Server) { s.StatusRefresh = 30 * time.Millisecond })
	agent := dialAgent(t, addr, "KidPC")
	wait(t, ev.statusCh, "identify status")
	agent.mu.Lock()
	agent.status = "LOCKED"
	agent.mu.Unlock()
	wait(t, ev.statusCh, "refresh status")
	sess := waitSession(t, s, "KidPC")
	deadline := time.Now().Add(2 * time.Second)
	for sess.Settings()["status"] != "LOCKED" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if sess.Settings()["status"] != "LOCKED" {
		t.Fatal("refresh did not update settings")
	}
	if r := agent.lastRequest(); r.Name == nil || *r.Name != "KidPC" {
		t.Fatal("refresh request is not addressed to the agent")
	}
}

func TestReconnectReplacesSessionWithoutDisconnect(t *testing.T) {
	s, addr, ev := newServer(t)
	first := dialAgent(t, addr, "KidPC")
	wait(t, ev.statusCh, "first status")
	old := waitSession(t, s, "KidPC")
	second := dialAgent(t, addr, "KidPC")
	wait(t, ev.statusCh, "second status")
	deadline := time.Now().Add(2 * time.Second)
	for s.SessionForHostname("KidPC") == old && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.SessionForHostname("KidPC") == old {
		t.Fatal("old session not replaced")
	}
	// The old connection is closed by the panel.
	first.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := first.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("old connection still open")
	}
	select {
	case h := <-ev.disconnCh:
		t.Fatalf("disconnect for %q while a replacement session exists", h)
	case <-time.After(100 * time.Millisecond):
	}
	if ok, _, found := s.PerformAction("127.0.0.1", "lock", nil); !found || !ok {
		t.Fatal("action did not reach the replacement session")
	}
	if second.lastRequest().Action != "lock" {
		t.Fatal("replacement agent did not get the action")
	}
	second.conn.Close()
	wait(t, ev.disconnCh, "disconnect")
}

func TestTimeoutDropsQueuedRequestAndEndsSession(t *testing.T) {
	s, addr, ev := newServer(t, func(s *Server) {
		s.ExchangeTimeout = 200 * time.Millisecond
		s.StatusRefresh = time.Hour // only the stalled actions talk to the agent
	})
	agent := dialAgent(t, addr, "KidPC")
	wait(t, ev.statusCh, "status")
	waitSession(t, s, "KidPC")
	stall := make(chan struct{})
	agent.mu.Lock()
	agent.stall = stall
	agent.mu.Unlock()
	defer close(stall)

	var wg sync.WaitGroup
	results := make([]string, 2)
	for i, action := range []string{"lock", "shutdown"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i], _ = s.PerformAction("127.0.0.1", action, nil)
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	for i, text := range results {
		if text != "timed out" && text != ErrSessionClosed.Error() {
			t.Errorf("action %d: %q", i, text)
		}
	}
	wait(t, ev.disconnCh, "disconnect after the stalled exchange")
	agent.mu.Lock()
	defer agent.mu.Unlock()
	for _, r := range agent.requests {
		if r.Action == "shutdown" {
			t.Fatal("the dropped shutdown was sent anyway")
		}
	}
}

func TestWrongSecretAgentIsNotRegistered(t *testing.T) {
	s, addr, ev := newServer(t)
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	a := &fakeAgent{t: t, hostname: "Evil", secret: "wrong-secret", conn: conn, answered: make(chan string, 10)}
	go a.serve()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	time.Sleep(200 * time.Millisecond)
	if s.SessionForHostname("Evil") != nil || len(ev.statusCh) != 0 {
		t.Fatal("agent with the wrong secret was registered")
	}
}

func TestNoSecretClosesConnection(t *testing.T) {
	_, addr, _ := newServer(t, func(s *Server) {
		s.Secret = func() (string, error) { return "", errors.New("no shared secret") }
	})
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection stayed open without a secret")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "panel"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLS(t *testing.T) {
	cert := selfSigned(t)
	s, addr, ev := newServer(t, func(s *Server) {
		s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	})
	raw, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	t.Cleanup(func() { conn.Close() })
	a := &fakeAgent{t: t, hostname: "TLSPC", secret: secret, conn: conn, status: "UNLOCKED",
		answered: make(chan string, 10)}
	go a.serve()
	wait(t, ev.statusCh, "status over TLS")
	if ok, _, _ := s.PerformAction("127.0.0.1", "lock", nil); !ok {
		t.Fatal("action over TLS failed")
	}
}

func TestConcurrentActionsAreSerialized(t *testing.T) {
	s, addr, ev := newServer(t)
	dialAgent(t, addr, "KidPC")
	wait(t, ev.statusCh, "status")
	waitSession(t, s, "KidPC")
	var wg sync.WaitGroup
	var failures sync.Map
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ok, text, _ := s.PerformAction("127.0.0.1", "extend_time", map[string]any{"minutes": int64(i)}); !ok {
				failures.Store(i, text)
			}
		}(i)
	}
	wg.Wait()
	failures.Range(func(k, v any) bool { t.Errorf("action %v failed: %v", k, v); return true })
}

func TestListenPortEnv(t *testing.T) {
	t.Setenv(PortEnv, " 12345 ")
	if ListenPort() != 12345 {
		t.Fatal("env port not used")
	}
	t.Setenv(PortEnv, "nope")
	if ListenPort() != DefaultPort {
		t.Fatal("bad env port not ignored")
	}
}
