package monitor

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kidpcmonitor/dispatcher"
	"kidpcmonitor/policy"
	"kidpcmonitor/protocol"
)

var _ dispatcher.Control = (*Control)(nil)

const testSecret = "integration-secret"

type session struct {
	t       *testing.T
	control *Control
	plat    *fakePlatform
	clock   *clockState
	dir     string
}

func newSession(t *testing.T) *session {
	t.Helper()
	dir := t.TempDir()
	clock := &clockState{now: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)}
	plat := newFakePlatform(nil)
	c, err := New(Config{
		Platform: plat, CurrentUser: "kid", DataDir: dir,
		Clock:       func() time.Time { return clock.now },
		Logger:      slog.New(slog.NewTextHandler(discard{}, nil)),
		StateLogger: slog.New(slog.NewTextHandler(discard{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &session{t, c, plat, clock, dir}
}

// do sends one signed request through the real dispatcher and parses the reply.
func (s *session) do(params protocol.RequestParams) *protocol.Response {
	s.t.Helper()
	params.Secret = testSecret
	params.ReqID = "r1"
	if protocol.WriteActions[params.Action] {
		params.Name = s.control.Hostname()
	}
	body, err := protocol.BuildRequest(params)
	if err != nil {
		s.t.Fatal(err)
	}
	reply := protocol.HandleRequest(body, testSecret, s.control.Hostname(), time.Now().Unix(), dispatcher.Handler(s.control))
	resp, err := protocol.ParseResponse(reply, testSecret, protocol.ResponseOptions{
		ExpectedName: s.control.Hostname(), ExpectedVersion: protocol.ProtocolVersion,
	}, time.Now().Unix())
	if err != nil {
		s.t.Fatalf("%s: %v\n%s", params.Action, err, reply)
	}
	return resp
}

func TestParentActionsPersistThroughTheDispatcher(t *testing.T) {
	s := newSession(t)
	if r := s.do(protocol.RequestParams{Action: "set", Var: "daily_limit", Val: 90}); !r.OK() {
		t.Fatalf("set daily_limit: %v", r.ErrorMessage)
	}
	if r := s.do(protocol.RequestParams{Action: "set", Var: "bed_time", Val: "21:30"}); !r.OK() {
		t.Fatalf("set bed_time: %v", r.ErrorMessage)
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "daily_settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"allowance": 90`, `"bed_time": "21:30"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("daily_settings.json lacks %s:\n%s", want, raw)
		}
	}

	r := s.do(protocol.RequestParams{Action: "get", Var: "settings"})
	if !r.OK() || r.Settings == nil {
		t.Fatalf("get settings: %+v", r)
	}
	if got := r.Settings["access_status"]; got != "Unlocked" {
		t.Errorf("access_status = %v", got)
	}

	if r := s.do(protocol.RequestParams{Action: "lock"}); !r.OK() {
		t.Fatalf("lock: %v", r.ErrorMessage)
	}
	if !s.control.ManualLockActive() || !s.plat.locked {
		t.Errorf("manual lock %v, workstation locked %v", s.control.ManualLockActive(), s.plat.locked)
	}
	s.do(protocol.RequestParams{Action: "extend", Val: 15})
	if s.control.ManualLockActive() || s.control.CumulativeExtensionSeconds() != 900 {
		t.Errorf("extend: manual %v, extension %d", s.control.ManualLockActive(), s.control.CumulativeExtensionSeconds())
	}
}

func TestFailedPopupIsAnInternalError(t *testing.T) {
	s := newSession(t)
	s.plat.fail["show_message"] = true
	r := s.do(protocol.RequestParams{Action: "message", Val: "dinner"})
	if r.OK() || r.ErrorCode != protocol.InternalError {
		t.Fatalf("want internal_error, got %+v", r)
	}
}

func TestLoopRunsWhileRequestsArrive(t *testing.T) {
	s := newSession(t)
	s.control.clock = func() time.Time { return policy.Wall(time.Now()) }
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.control.Run(ctx) }()

	for i := 0; i < 50; i++ {
		s.do(protocol.RequestParams{Action: "get", Var: "settings"})
		s.do(protocol.RequestParams{Action: "set", Var: "daily_limit", Val: 60 + i})
		s.control.ScreenLocked()
	}
	cancel()
	wg.Wait()
}

func TestRunStopsWhenCancelled(t *testing.T) {
	s := newSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.control.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
