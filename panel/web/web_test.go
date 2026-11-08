package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kidpcmonitor/panel/auth"
	"kidpcmonitor/panel/store"
	"kidpcmonitor/protocol"
)

func newApp(t *testing.T, rev Reverse) *App {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, store.DBFilename))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	app, err := New(Config{Store: s, Auth: auth.Files{Dir: dir}, Reverse: rev, ReversePort: 9998})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func do(app *App, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHeadAndOptions(t *testing.T) {
	app := newApp(t, nil)
	head := do(app, "HEAD", "/agent/v1/discover")
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("HEAD = %d %q %q", head.Code, head.Header().Get("Content-Type"), head.Body.String())
	}
	opts := do(app, "OPTIONS", "/action")
	if opts.Code != 200 || opts.Header().Get("Allow") != "OPTIONS, POST" {
		t.Fatalf("OPTIONS = %d Allow %q", opts.Code, opts.Header().Get("Allow"))
	}
}

type panicky struct{}

func (panicky) Session(string) (string, map[string]any, bool) { panic("boom") }
func (panicky) PerformAction(string, string, map[string]any) (bool, string, bool) {
	return false, "", false
}
func (panicky) GetLogs(string) (*protocol.LogsResult, error) { return nil, nil }

func TestPanicIsInternalServerError(t *testing.T) {
	app := newApp(t, panicky{})
	rec := do(app, "GET", "/logs/10.0.0.1")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "500 Internal Server Error") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != DynamicCacheControl {
		t.Fatal("500 page without the dynamic cache headers")
	}
}

func TestStaticRejectsTraversalAndReadme(t *testing.T) {
	app := newApp(t, nil)
	for _, p := range []string{"/static/../web.go", "/static/README.md", "/static/css", "/static/css/../../x"} {
		if rec := do(app, "GET", p); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d", p, rec.Code)
		}
	}
	if rec := do(app, "GET", "/static/js/home.js"); rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("static js = %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

func TestDamagedAuthFileLocksThePanel(t *testing.T) {
	app := newApp(t, nil)
	path := app.auth.SavePath()
	if err := os.WriteFile(path, []byte(`{"secret_key": "cccccccccccccccc", "password_hash": `), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/login", "/set-password", "/control/KID-PC", "/no-such-page"} {
		rec := do(app, "GET", p)
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != auth.LockedText(path) {
			t.Errorf("GET %s = %d %q", p, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Header().Get("Cache-Control") != DynamicCacheControl {
			t.Errorf("GET %s headers %v", p, rec.Header())
		}
	}
	for _, p := range []string{"/agent/v1/discover", "/static/css/panel.css"} {
		if rec := do(app, "GET", p); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d while locked", p, rec.Code)
		}
	}
	if rec := do(app, "POST", "/set-password"); rec.Code != http.StatusBadRequest {
		t.Errorf("POST /set-password = %d", rec.Code)
	}
}

func TestSnapshotFromEarlierDayIsNotLabelledToday(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, store.DBFilename))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loc := time.FixedZone("", -6*3600)
	s.Loc = loc
	app, err := New(Config{Store: s, Auth: auth.Files{Dir: dir}, Reverse: fakeReverse{obj{}}, ReversePort: 9998})
	if err != nil {
		t.Fatal(err)
	}
	info := map[string]any{
		"hostname": "KID-PC", "current_user": "kid", "ip": "192.168.1.10", "reachable": true,
		"daily_limit": 1, "accumulated_seconds": 61, "cumulative_extension_seconds": 3600,
		"effective_limit_minutes": 61.0, "time_remaining": "0 minutes",
		"access_status": "Locked — daily limit reached",
	}
	recorded := time.Date(2026, 11, 4, 18, 13, 27, 0, loc)
	s.Now = func() time.Time { return recorded }
	if err := s.RecordPollInspect("192.168.1.10", info, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSnapshot(info); err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return time.Date(2026, 11, 8, 10, 0, 0, 0, loc) }

	for _, path := range []string{"/control/192.168.1.10", "/control/192.168.1.10/stats"} {
		body := normalizeHTML(do(app, http.MethodGet, path).Body.String())
		if !strings.Contains(body, `<h2 class="action-title">Nov 4</h2>`) {
			t.Errorf("%s: heading is not the snapshot day:\n%s", path, body)
		}
		if strings.Contains(body, "Extra today") || !strings.Contains(body, "<dt>Extra that day</dt>") {
			t.Errorf("%s: extension label still says today:\n%s", path, body)
		}
	}
}
