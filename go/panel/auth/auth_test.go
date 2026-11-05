package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSavePasswordKeepsKeyAndVerifies(t *testing.T) {
	dir := t.TempDir()
	f := Files{Dir: dir}
	if f.PasswordConfigured() {
		t.Fatal("configured before saving")
	}
	key, err := f.SavePassword("supersecret1")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 64 {
		t.Fatalf("new secret key %q, want 64 hex chars", key)
	}
	rec := f.Load()
	if !rec.VerifyPassword("supersecret1") || rec.VerifyPassword("wrong") {
		t.Fatal("stored hash does not verify")
	}
	if !strings.HasPrefix(rec.PasswordHash(), "scrypt:32768:8:1$") {
		t.Fatalf("hash %q is not werkzeug's default scrypt", rec.PasswordHash())
	}
	again, err := f.SavePassword("another-one")
	if err != nil || again != key {
		t.Fatalf("second save changed the key: %q -> %q (%v)", key, again, err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(f.SavePath())
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("auth file mode %v, %v", st.Mode(), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func TestLegacyPathUsedOnlyWithoutCanonical(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(t.TempDir(), AuthFile)
	if err := os.WriteFile(legacy, []byte(`{"password_hash": "legacy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := Files{Dir: dir, Legacy: []string{filepath.Join(dir, "missing.json"), legacy}}
	if got := f.Load().PasswordHash(); got != "legacy" {
		t.Fatalf("legacy hash = %q", got)
	}
	if _, err := f.SavePassword("supersecret1"); err != nil {
		t.Fatal(err)
	}
	if f.ReadPath() != f.SavePath() || f.Load().PasswordHash() == "legacy" {
		t.Fatal("canonical file did not take over from the legacy one")
	}
}

func roundTrip(t *testing.T, m *Sessions, s *Session) *Session {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Save(rec, s)
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return m.Load(req)
}

func TestSessionRoundTripAndFlashes(t *testing.T) {
	m := NewSessions("c" + strings.Repeat("x", 31))
	s := &Session{}
	token := s.CSRFToken()
	if len(token) != 43 || s.CSRFToken() != token {
		t.Fatalf("csrf token %q", token)
	}
	s.SetAuthenticated(true)
	s.AddFlash("success", "Password saved.")
	got := roundTrip(t, m, s)
	if !got.Authenticated() || !got.ValidCSRF(token) || got.ValidCSRF(token+"x") || got.ValidCSRF("") {
		t.Fatal("session did not survive the cookie")
	}
	if f := got.PopFlashes(); len(f) != 1 || f[0] != (Flash{"success", "Password saved."}) {
		t.Fatalf("flashes = %v", f)
	}
	if !got.Modified() || len(got.PopFlashes()) != 0 {
		t.Fatal("flashes not consumed")
	}
}

func TestSessionRejectsForgedExpiredAndRekeyed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := NewSessions("first-secret-key-123")
	m.Now = func() time.Time { return now }
	s := &Session{}
	s.SetAuthenticated(true)
	rec := httptest.NewRecorder()
	m.Save(rec, s)
	cookie := rec.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("cookie attributes %+v", cookie)
	}
	load := func(value string) bool {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
		return m.Load(req).Authenticated()
	}
	if !load(cookie.Value) {
		t.Fatal("fresh cookie rejected")
	}
	payload, sig, _ := strings.Cut(cookie.Value, ".")
	if load(payload+"x."+sig) || load(payload) || load("garbage") {
		t.Fatal("forged cookie accepted")
	}
	// A Flask cookie (itsdangerous format) is simply not a session here.
	if load("eyJfY3NyZl90b2tlbiI6InRva2VuIn0.ZxYz.abc") {
		t.Fatal("flask cookie accepted")
	}
	now = now.Add(SessionMaxAge + time.Second)
	if load(cookie.Value) {
		t.Fatal("expired cookie accepted")
	}
	now = now.Add(-SessionMaxAge)
	m.SetSecret("second-secret-key-12")
	if load(cookie.Value) {
		t.Fatal("cookie signed with the old secret accepted")
	}
}

func TestSessionSaveOnlyWhenModifiedAndDeletesWhenEmpty(t *testing.T) {
	m := NewSessions("0123456789abcdef")
	rec := httptest.NewRecorder()
	m.Save(rec, &Session{})
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("unmodified session wrote a cookie")
	}
	s := &Session{}
	s.SetAuthenticated(true)
	s = roundTrip(t, m, s)
	s.SetAuthenticated(false)
	rec = httptest.NewRecorder()
	m.Save(rec, s)
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].MaxAge >= 0 {
		t.Fatalf("emptied session not deleted: %+v", c)
	}
	if rec.Header().Get("Vary") != "Cookie" {
		t.Fatal("missing Vary: Cookie")
	}
	m.Secure = true
	s.SetAuthenticated(true)
	rec = httptest.NewRecorder()
	m.Save(rec, s)
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("Secure not set under TLS")
	}
}

func TestGeneratePasswordHashSalts(t *testing.T) {
	a, err := GeneratePasswordHash("pw")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePasswordHash("pw")
	if a == b {
		t.Fatal("two hashes share a salt")
	}
	salt := strings.Split(a, "$")[1]
	if len(salt) != 16 || strings.Trim(salt, saltChars) != "" {
		t.Fatalf("salt %q", salt)
	}
}

func TestDamagedAuthFileIsAProblemNotNoPassword(t *testing.T) {
	cases := map[string]func(path string) error{
		"not UTF-8": func(p string) error { return os.WriteFile(p, []byte("{\"password_hash\": \"\xff\"}"), 0o600) },
		"truncated": func(p string) error { return os.WriteFile(p, []byte(`{"password_hash": `), 0o600) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
		"old format": func(p string) error {
			return os.WriteFile(p, []byte(`{"salt": "00ff", "hash": "abcd"}`), 0o600)
		},
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		cases["unreadable"] = func(p string) error {
			if err := os.WriteFile(p, []byte(`{"password_hash": "x"}`), 0o600); err != nil {
				return err
			}
			return os.Chmod(p, 0)
		}
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			f := Files{Dir: t.TempDir()}
			legacy := filepath.Join(t.TempDir(), AuthFile)
			if err := os.WriteFile(legacy, []byte(`{"password_hash": "legacy"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			f.Legacy = []string{legacy}
			if err := damage(f.SavePath()); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(f.SavePath(), 0o600)
			if f.ReadPath() != f.SavePath() {
				t.Fatal("damaged canonical file skipped for the legacy one")
			}
			if f.Problem() == nil || f.Load() != nil {
				t.Fatalf("Problem() = %v, Load() = %v", f.Problem(), f.Load())
			}
			if _, err := f.SavePassword("attacker123"); err == nil {
				t.Fatal("SavePassword replaced a damaged auth file")
			}
		})
	}
	f := Files{Dir: t.TempDir()}
	if rec, err := f.Read(); rec != nil || err != nil {
		t.Fatalf("missing file: Read() = %v, %v", rec, err)
	}
}
