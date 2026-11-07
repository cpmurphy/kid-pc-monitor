package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"kidpcmonitor/panel/auth"
	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/panel/store"
	"kidpcmonitor/protocol"
)

// The golden vectors are the checked-in contract, originally captured by
// driving the Python panel. Every request is replayed here against the same
// seeded state and must get the same response.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "panelweb", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyval.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(obj)
}

func str(v any) string { s, _ := v.(string); return s }

func list(v any) []any { l, _ := v.([]any); return l }

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, _, err := pyval.FromISOFormat(s)
	if err != nil {
		t.Fatalf("bad time %q", s)
	}
	return tm
}

// normalizeHTML mirrors normalize_html in the generator.
var (
	csrfRe   = regexp.MustCompile(`(name="csrf-token" content="|name="csrf_token" value=")[^"]*(")`)
	numRefRe = regexp.MustCompile(`&#(?:(\d+)|[xX]([0-9a-fA-F]+));`)
	wsRe     = regexp.MustCompile(`[ \t\n\r\f\v]+`)
	scrapeRe = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)
)

func normalizeHTML(s string) string {
	s = csrfRe.ReplaceAllString(s, "${1}CSRF${2}")
	s = numRefRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := numRefRe.FindStringSubmatch(m)
		var n int64
		if sub[1] != "" {
			n, _ = strconv.ParseInt(sub[1], 10, 32)
		} else {
			n, _ = strconv.ParseInt(sub[2], 16, 32)
		}
		return string(rune(n))
	})
	s = wsRe.ReplaceAllString(s, " ")
	return strings.TrimSpace(strings.ReplaceAll(s, "> <", "><"))
}

// fakeReverse mirrors FakeReverse in the generator.
type fakeReverse struct{ sessions obj }

func (f fakeReverse) spec(ip string) (obj, bool) {
	s, ok := f.sessions[ip].(obj)
	return s, ok
}

func (f fakeReverse) Session(ip string) (string, map[string]any, bool) {
	s, ok := f.spec(ip)
	if !ok {
		return "", nil, false
	}
	settings := map[string]any{}
	for k, v := range s["settings"].(obj) {
		settings[k] = v
	}
	return str(s["hostname"]), settings, true
}

func (f fakeReverse) PerformAction(ip, action string, payload map[string]any) (bool, string, bool) {
	if _, ok := f.spec(ip); !ok {
		return false, "", false
	}
	fields, err := format.ActionRequestFields(action, payload)
	if err != nil {
		return false, format.InvalidActionMessage(action, err), true
	}
	var v, tail any
	if fields.Var != nil {
		v = *fields.Var
	}
	if fields.Tail != nil {
		tail = *fields.Tail
	}
	return true, fmt.Sprintf("%s var=%s val=%s tail=%s", fields.Action, pyval.Str(v), pyval.Str(fields.Val), pyval.Str(tail)), true
}

func (f fakeReverse) GetLogs(ip string) (*protocol.LogsResult, error) {
	s, _ := f.spec(ip)
	if e, ok := s["logs_error"]; ok {
		return nil, errors.New(str(e))
	}
	lines := []string{}
	for _, l := range list(s["logs"]) {
		lines = append(lines, str(l))
	}
	return &protocol.LogsResult{Lines: lines, Truncated: s["truncated"] == true,
		Path: `C:\ProgramData\KidPCMonitor\pc_control.log`}, nil
}

func seed(t *testing.T, s *store.Store, app *App, steps []any) {
	t.Helper()
	for _, raw := range steps {
		st := raw.(obj)
		at := mustTime(t, str(st["at"]))
		s.Now = func() time.Time { return at }
		args := st["args"].(obj)
		info, _ := args["pc_info"].(obj)
		var err error
		switch st["op"] {
		case "record_poll_inspect":
			err = s.RecordPollInspect(str(args["ip"]), info, time.Time{})
		case "save_snapshot":
			err = s.SaveSnapshot(info)
		case "save_poll_snapshot":
			err = s.SavePollSnapshot(info)
		case "reverse_status":
			settings := map[string]any{}
			for k, v := range args["settings"].(obj) {
				settings[k] = v
			}
			app.RecordReverseStatus(str(args["hostname"]), str(args["ip"]), settings)
		case "reverse_disconnect":
			app.RecordReverseDisconnect(str(args["hostname"]), str(args["ip"]))
		default:
			t.Fatalf("unknown seed op %v", st["op"])
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

var recordedHeaders = []string{"Location", "Content-Type", "Cache-Control", "Pragma", "Expires", "Allow"}

func TestConstants(t *testing.T) {
	v := loadVectors(t)
	if v["panel_username"] != PanelUsername || v["dynamic_cache_control"] != DynamicCacheControl {
		t.Fatalf("constants: %v %v", v["panel_username"], v["dynamic_cache_control"])
	}
}

func TestScenarios(t *testing.T) {
	v := loadVectors(t)
	loc := time.FixedZone("", -5*3600)
	if v["tz"] != "-05:00" {
		t.Fatalf("tz %v", v["tz"])
	}
	now := mustTime(t, str(v["now"]))
	for _, raw := range list(v["scenarios"]) {
		sc := raw.(obj)
		t.Run(str(sc["name"]), func(t *testing.T) {
			dir := t.TempDir()
			s, err := store.Open(filepath.Join(dir, store.DBFilename))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.Loc = loc
			files := auth.Files{Dir: dir}
			if rec, ok := sc["auth"].(obj); ok {
				text := auth.FormatRecordJSON(str(rec["secret_key"]), str(rec["password_hash"]))
				if err := os.WriteFile(files.SavePath(), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			authText, damaged := sc["auth_text"].(string)
			if damaged {
				if err := os.WriteFile(files.SavePath(), []byte(authText), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			app, err := New(Config{Store: s, Auth: files, Reverse: fakeReverse{v["sessions"].(obj)}, ReversePort: 9998})
			if err != nil {
				t.Fatal(err)
			}
			seed(t, s, app, list(v["seed"]))
			s.Now = func() time.Time { return now }
			runRequests(t, app, list(sc["requests"]), dir)
			if got := files.PasswordConfigured(); got != sc["password_set_after"] {
				t.Errorf("password set after scenario = %v, want %v", got, sc["password_set_after"])
			}
			if damaged {
				after, _ := os.ReadFile(files.SavePath())
				if got := string(after) == authText; got != sc["auth_text_unchanged"] {
					t.Errorf("auth file unchanged = %v, want %v", got, sc["auth_text_unchanged"])
				}
			}
		})
	}
}

// runRequests replays requests; authDir is shown as <DIR> in text bodies.
func runRequests(t *testing.T, app *App, requests []any, authDir string) {
	cookies := map[string]string{}
	csrf := ""
	for i, raw := range requests {
		spec := raw.(obj)
		method, rawPath := str(spec["method"]), str(spec["path"])
		pathPart, query, _ := strings.Cut(rawPath, "?")
		target := (&url.URL{Path: pathPart, RawQuery: query}).String()
		var body string
		headers := http.Header{}
		if h, ok := spec["headers"].(obj); ok {
			for k, v := range h {
				headers.Set(k, str(v))
			}
		}
		form, hasForm := spec["form"].(obj)
		switch spec["csrf"] {
		case "header":
			headers.Set("X-CSRF-Token", csrf)
		case "form":
			if !hasForm {
				form, hasForm = obj{}, true
			}
			form = merge(form, obj{"csrf_token": csrf})
		}
		if j, ok := spec["json"]; ok {
			enc, err := pyval.EncodeJSON(j)
			if err != nil {
				t.Fatal(err)
			}
			body = enc
			headers.Set("Content-Type", "application/json")
		} else if hasForm {
			vals := url.Values{}
			for k, v := range form {
				vals.Set(k, str(v))
			}
			body = vals.Encode()
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header = headers
		for name, value := range cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		res := rec.Result()
		for _, c := range res.Cookies() {
			if c.MaxAge < 0 {
				delete(cookies, c.Name)
			} else {
				cookies[c.Name] = c.Value
			}
		}
		text := rec.Body.String()
		if m := scrapeRe.FindStringSubmatch(text); m != nil {
			csrf = m[1]
		}

		label := fmt.Sprintf("request %d: %s %s", i, method, rawPath)
		want := spec["response"].(obj)
		if got := int64(res.StatusCode); got != want["status"] {
			t.Errorf("%s: status %d, want %v", label, got, want["status"])
		}
		wantHeaders := want["headers"].(obj)
		for _, h := range recordedHeaders {
			got, present := res.Header[h]
			w, wantPresent := wantHeaders[h]
			value := strings.Join(got, ", ")
			if h == "Allow" {
				methods := strings.Split(value, ", ")
				sort.Strings(methods)
				value = strings.Join(methods, ", ")
			}
			if present != wantPresent || (present && value != w) {
				t.Errorf("%s: header %s = %q (present %v), want %q (present %v)", label, h, got, present, w, wantPresent)
			}
		}
		switch {
		case want["json"] != nil:
			got, err := pyval.DecodeJSON(rec.Body.Bytes())
			if err != nil || !reflect.DeepEqual(got, want["json"]) {
				t.Errorf("%s: json %s, want %v", label, text, want["json"])
			}
		case want["html"] != nil || hasKey(want, "html"):
			got := normalizeHTML(text)
			if w := str(want["html"]); got != w {
				t.Errorf("%s: html differs\n%s", label, firstDifference(got, w))
			}
		case hasKey(want, "text"):
			got := strings.ReplaceAll(strings.ReplaceAll(text, authDir, "<DIR>"), `\`, "/")
			if w := str(want["text"]); got != w {
				t.Errorf("%s: text differs\n%s", label, firstDifference(got, w))
			}
		default:
			sum := sha256.Sum256(rec.Body.Bytes())
			if hex.EncodeToString(sum[:]) != want["sha256"] || int64(rec.Body.Len()) != want["length"] {
				t.Errorf("%s: static body differs (%d bytes)", label, rec.Body.Len())
			}
		}
	}
}

func hasKey(m obj, k string) bool { _, ok := m[k]; return ok }

func firstDifference(got, want string) string {
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	from := max(0, i-120)
	clip := func(s string) string {
		end := min(len(s), i+160)
		if from > len(s) {
			return ""
		}
		return s[from:end]
	}
	return fmt.Sprintf(" at byte %d\n got  …%s\n want …%s", i, clip(got), clip(want))
}
