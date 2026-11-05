package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
