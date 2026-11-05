package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionCookieName matches Flask's, so a stale Flask cookie is simply
// replaced (it does not verify here, and the reverse).
const SessionCookieName = "session"

// SessionMaxAge is how long a session is valid after its last change
// (Flask's PERMANENT_SESSION_LIFETIME, which it applies to every session).
const SessionMaxAge = 31 * 24 * time.Hour

// Flash is a one-time message shown on the next rendered page.
type Flash struct {
	Category string `json:"c"`
	Message  string `json:"m"`
}

// Session is the parent's session: login state, CSRF token and pending
// flash messages. Change it only through its methods so the cookie is
// rewritten.
type Session struct {
	data     sessionData
	modified bool
}

type sessionData struct {
	Authenticated bool    `json:"a,omitempty"`
	CSRF          string  `json:"c,omitempty"`
	Flashes       []Flash `json:"f,omitempty"`
	Issued        int64   `json:"t"`
}

// Authenticated reports whether the parent has logged in.
func (s *Session) Authenticated() bool { return s.data.Authenticated }

// SetAuthenticated logs the parent in or out.
func (s *Session) SetAuthenticated(v bool) {
	if s.data.Authenticated != v {
		s.data.Authenticated = v
		s.modified = true
	}
}

// CSRFToken returns the session's CSRF token, creating one on first use
// (web_panel._csrf_token: secrets.token_urlsafe(32)).
func (s *Session) CSRFToken() string {
	if s.data.CSRF == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err) // crypto/rand never fails on supported platforms
		}
		s.data.CSRF = base64.RawURLEncoding.EncodeToString(b)
		s.modified = true
	}
	return s.data.CSRF
}

// ValidCSRF reports whether supplied matches the session's token
// (web_panel._csrf_valid). A session without a token accepts nothing.
func (s *Session) ValidCSRF(supplied string) bool {
	expected := s.data.CSRF
	if expected == "" || supplied == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(supplied)) == 1
}

// AddFlash queues a message for the next rendered page (flask.flash).
func (s *Session) AddFlash(category, message string) {
	s.data.Flashes = append(s.data.Flashes, Flash{category, message})
	s.modified = true
}

// PopFlashes returns and clears the queued messages
// (flask.get_flashed_messages).
func (s *Session) PopFlashes() []Flash {
	flashes := s.data.Flashes
	if len(flashes) > 0 {
		s.data.Flashes = nil
		s.modified = true
	}
	return flashes
}

// Modified reports whether the session changed since it was loaded.
func (s *Session) Modified() bool { return s.modified }

func (s *Session) empty() bool {
	return !s.data.Authenticated && s.data.CSRF == "" && len(s.data.Flashes) == 0
}

// Sessions signs and verifies session cookies. The signing key comes from
// the panel secret and can be replaced (when a password is first set).
type Sessions struct {
	mu  sync.RWMutex
	key []byte

	// Secure marks the cookie HTTPS-only (set when the panel serves TLS).
	Secure bool
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// NewSessions signs with a key derived from secret.
func NewSessions(secret string) *Sessions {
	s := &Sessions{Now: time.Now}
	s.SetSecret(secret)
	return s
}

// SetSecret replaces the signing secret; existing cookies stop verifying.
func (m *Sessions) SetSecret(secret string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("kid-pc-monitor web panel session v1"))
	m.mu.Lock()
	m.key = mac.Sum(nil)
	m.mu.Unlock()
}

func (m *Sessions) sign(payload string) string {
	m.mu.RLock()
	mac := hmac.New(sha256.New, m.key)
	m.mu.RUnlock()
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Load returns the request's session, or an empty one when the cookie is
// missing, forged or expired.
func (m *Sessions) Load(r *http.Request) *Session {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return &Session{}
	}
	return m.decode(c.Value)
}

func (m *Sessions) decode(value string) *Session {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(m.sign(payload))) {
		return &Session{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return &Session{}
	}
	var data sessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return &Session{}
	}
	issued := time.Unix(data.Issued, 0)
	if age := m.Now().Sub(issued); age > SessionMaxAge || age < -time.Minute {
		return &Session{}
	}
	return &Session{data: data}
}

func (m *Sessions) encode(s *Session) string {
	s.data.Issued = m.Now().Unix()
	raw, _ := json.Marshal(s.data)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + m.sign(payload)
}

// Save writes the cookie when the session changed: the new value, or a
// deletion when it is now empty (as Flask does). Call it before the
// response header is written.
func (m *Sessions) Save(w http.ResponseWriter, s *Session) {
	if !s.modified {
		return
	}
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
	}
	if s.empty() {
		cookie.MaxAge = -1
	} else {
		cookie.Value = m.encode(s)
	}
	http.SetCookie(w, cookie)
	w.Header().Add("Vary", "Cookie")
	s.modified = false
}

// RandomHex is secrets.token_hex(n).
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
