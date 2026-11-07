// Package web is the parent web panel's HTTP app (web_panel.py): the
// dashboard, per-PC control, daily settings, agent log and usage pages,
// password login, and the JSON endpoints the pages' scripts call.
//
// It serves the same routes, templates (rewritten for html/template), static
// files, cookies-aside headers and JSON as the original Flask app.
// testdata/panelweb/vectors.json is the checked-in contract from that app,
// and vectors_test.go replays every request against this package, comparing
// status, headers and normalized bodies.
//
// static/ is the panel's CSS and JavaScript (embedded; Go cannot embed files
// outside the module). A change there updates the SHA-256 in the panelweb
// vectors in the same commit.
//
// # Known differences from the Python implementation
//
//   - Session cookies are package auth's format (see there).
//   - In href and src attributes, html/template percent-encodes ' ( ) that
//     werkzeug leaves as is; the URLs are equivalent.
//   - A JSON /action body that is not an object counts as empty (Python
//     fails with a server error).
//   - Static files carry no ETag or Last-Modified (embedded files have no
//     modification time); Cache-Control is no-cache, as Flask sends.
//   - werkzeug's slash merging ("/control//x" redirecting to "/control/x")
//     is not reproduced; such paths are 404.
package web

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"kidpcmonitor/panel/auth"
	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/panel/reverse"
	"kidpcmonitor/panel/store"
	"kidpcmonitor/protocol"
)

// Constants from web_panel.py and agent_poller.py.
const (
	PanelUsername       = "Kid PC Monitor"
	DynamicCacheControl = "private, no-cache, no-store, must-revalidate, max-age=0"
	PollIntervalSec     = 60
)

// Reverse is the live agent sessions the panel drives (reverse.Server).
type Reverse interface {
	// Session returns the agent hostname and latest settings for ip.
	Session(ip string) (hostname string, settings map[string]any, ok bool)
	// PerformAction runs a panel action; found is false without a session.
	PerformAction(ip, action string, payload map[string]any) (ok bool, text string, found bool)
	// GetLogs fetches the agent's log tail.
	GetLogs(ip string) (*protocol.LogsResult, error)
}

// Config wires the app to its stores.
type Config struct {
	Store *store.Store // also the clock (Store.Now / Store.Loc)
	Auth  auth.Files
	// Reverse may be nil (no reverse listener).
	Reverse Reverse
	// SecretKey overrides the session secret (KID_PC_MONITOR_SECRET).
	SecretKey string
	// SecureCookies marks session cookies HTTPS-only.
	SecureCookies bool
	// ReversePort is advertised by /agent/v1/discover.
	ReversePort int
	Logger      *slog.Logger
}

// App is the panel's http.Handler.
type App struct {
	store       *store.Store
	auth        auth.Files
	reverse     Reverse
	sessions    *auth.Sessions
	tpl         *templates
	static      fs.FS
	reversePort int
	log         *slog.Logger
}

// New builds the app. The session secret is cfg.SecretKey, else the auth
// file's secret_key, else a random one (create_app).
func New(cfg Config) (*App, error) {
	tpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	secret := cfg.SecretKey
	if secret == "" {
		secret = cfg.Auth.Load().SecretKey()
	}
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		secret = hex.EncodeToString(b)
	}
	sessions := auth.NewSessions(secret)
	sessions.Secure = cfg.SecureCookies
	sessions.Now = func() time.Time { return cfg.Store.Now() }
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &App{
		store:       cfg.Store,
		auth:        cfg.Auth,
		reverse:     cfg.Reverse,
		sessions:    sessions,
		tpl:         tpl,
		static:      staticRoot(),
		reversePort: cfg.ReversePort,
		log:         logger,
	}, nil
}

func (a *App) now() time.Time { return a.store.Now().In(a.store.Loc) }

// reqCtx is one request in flight.
type reqCtx struct {
	app        *App
	r          *http.Request
	sess       *auth.Session
	status     int
	header     http.Header
	body       bytes.Buffer
	static     bool
	popped     []flashMsg
	poppedDone bool
}

func (c *reqCtx) flashes() []flashMsg {
	if !c.poppedDone {
		for _, f := range c.sess.PopFlashes() {
			c.popped = append(c.popped, flashMsg{f.Category, f.Message})
		}
		c.poppedDone = true
	}
	return c.popped
}

func (c *reqCtx) flash(message, category string) { c.sess.AddFlash(category, message) }

func (c *reqCtx) write(status int, contentType string, body []byte) {
	c.status = status
	c.header.Set("Content-Type", contentType)
	c.body.Reset()
	c.body.Write(body)
}

func (c *reqCtx) html(status int, body string) {
	c.write(status, "text/html; charset=utf-8", []byte(body))
}

func (c *reqCtx) render(page string, data map[string]any) {
	out, err := c.app.tpl.render(page, &view{c: c, D: data})
	if err != nil {
		c.app.log.Error("Template failed", "page", page, "err", err)
		c.abort(http.StatusInternalServerError)
		return
	}
	c.write(http.StatusOK, "text/html; charset=utf-8", out)
}

func (c *reqCtx) json(v any) {
	out, err := pyval.EncodeJSON(v)
	if err != nil {
		c.app.log.Error("JSON response failed", "err", err)
		c.abort(http.StatusInternalServerError)
		return
	}
	c.write(http.StatusOK, "application/json", []byte(out+"\n"))
}

// redirect is flask.redirect: 302 with werkzeug's body.
func (c *reqCtx) redirect(location string) {
	esc := htmlEscape(location)
	c.html(http.StatusFound, "<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n"+
		"<h1>Redirecting...</h1>\n<p>You should be redirected automatically to the target URL: "+
		`<a href="`+esc+`">`+esc+"</a>. If not, click the link.\n")
	c.header.Set("Location", location)
}

var httpErrors = map[int][2]string{
	400: {"Bad Request", "The browser (or proxy) sent a request that this server could not understand."},
	404: {"Not Found", "The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again."},
	405: {"Method Not Allowed", "The method is not allowed for the requested URL."},
	500: {"Internal Server Error", "The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application."},
}

// abort is flask.abort: werkzeug's error page.
func (c *reqCtx) abort(code int) {
	e := httpErrors[code]
	c.html(code, fmt.Sprintf("<!doctype html>\n<html lang=en>\n<title>%d %s</title>\n<h1>%s</h1>\n<p>%s</p>\n",
		code, e[0], e[0], e[1]))
}

// htmlEscape is markupsafe.escape.
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(s)
}

// ServeHTTP runs the Flask request cycle: CSRF check (before_request),
// routing, the view, cache headers (after_request), then the session cookie.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := &reqCtx{app: a, r: r, sess: a.sessions.Load(r), status: http.StatusOK, header: http.Header{}}
	func() {
		defer func() {
			if p := recover(); p != nil {
				a.log.Error("Request failed", "path", r.URL.Path, "panic", p)
				c.header = http.Header{}
				c.abort(http.StatusInternalServerError)
			}
		}()
		if r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, "/agent/v1/") && !c.csrfValid() {
			c.abort(http.StatusBadRequest)
			return
		}
		if !a.authUsable(c) {
			return
		}
		a.route(c)
	}()
	if !c.static {
		c.header.Set("Cache-Control", DynamicCacheControl)
		c.header.Set("Pragma", "no-cache")
		c.header.Set("Expires", "0")
	}
	rec := &headerOnly{h: c.header}
	a.sessions.Save(rec, c.sess)
	for k, v := range c.header {
		w.Header()[k] = v
	}
	w.WriteHeader(c.status)
	if r.Method != http.MethodHead {
		w.Write(c.body.Bytes())
	}
}

// authUsable serves the locked page, and reports false, when the auth file
// exists but cannot be used (require_usable_auth_file): a damaged password
// file must not read as "no password set", which would let anyone on the
// network in or set a password of their own. Static files and the agent
// discovery endpoint stay available.
func (a *App) authUsable(c *reqCtx) bool {
	p := c.r.URL.Path
	if strings.HasPrefix(p, "/agent/v1/") || (strings.HasPrefix(p, "/static/") && len(p) > len("/static/")) {
		return true
	}
	problem := a.auth.Problem()
	if problem == nil {
		return true
	}
	a.log.Error("Web panel locked: " + problem.Error())
	c.status = http.StatusServiceUnavailable
	c.header.Set("Content-Type", "text/plain; charset=utf-8")
	c.body.WriteString(auth.LockedText(a.auth.ReadPath()))
	return false
}

// headerOnly lets Sessions.Save add its cookie to the buffered headers.
type headerOnly struct{ h http.Header }

func (h *headerOnly) Header() http.Header         { return h.h }
func (h *headerOnly) Write(b []byte) (int, error) { return len(b), nil }
func (h *headerOnly) WriteHeader(int)             {}

func (c *reqCtx) csrfValid() bool {
	supplied := c.r.PostFormValue("csrf_token")
	if supplied == "" {
		supplied = c.r.Header.Get("X-CSRF-Token")
	}
	return c.sess.ValidCSRF(supplied)
}

// route matches werkzeug's URL map: 404 for no rule, 405 for a rule that
// does not take the method (GET rules also take HEAD; every rule OPTIONS).
func (a *App) route(c *reqCtx) {
	p := c.r.URL.Path
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	one := func(prefix string) (string, bool) { // /prefix/<value> (no slash in value)
		if len(seg) == 2 && seg[0] == prefix && seg[1] != "" {
			return seg[1], true
		}
		return "", false
	}
	type rule struct {
		methods string
		view    func()
	}
	var match *rule
	switch {
	case p == "/":
		match = &rule{"GET", func() { a.loginRequired(c, a.index) }}
	case p == "/login":
		match = &rule{"GET POST", func() { a.login(c) }}
	case p == "/logout":
		match = &rule{"GET", func() { a.logout(c) }}
	case p == "/set-password":
		match = &rule{"GET POST", func() { a.setPassword(c) }}
	case p == "/agent/v1/discover":
		match = &rule{"GET", func() { a.discover(c) }}
	case p == "/action":
		match = &rule{"POST", func() { a.loginRequired(c, a.action) }}
	case strings.HasPrefix(p, "/static/") && len(p) > len("/static/"):
		match = &rule{"GET", func() { a.serveStatic(c, strings.TrimPrefix(p, "/static/")) }}
	case strings.HasPrefix(p, "/usage/") && len(p) > len("/usage/"):
		user := strings.TrimPrefix(p, "/usage/")
		match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.usage(c, user) }) }}
	case len(seg) == 3 && seg[0] == "control" && seg[1] != "" && seg[2] == "poll-meta":
		match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.pollMeta(c, seg[1]) }) }}
	case len(seg) == 3 && seg[0] == "control" && seg[1] != "" && seg[2] == "stats":
		match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.stats(c, seg[1]) }) }}
	default:
		if v, ok := one("control"); ok {
			match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.control(c, v) }) }}
		} else if v, ok := one("logs"); ok {
			match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.logs(c, v) }) }}
		} else if v, ok := one("daily_settings"); ok {
			match = &rule{"GET", func() { a.loginRequired(c, func(c *reqCtx) { a.dailySettings(c, v) }) }}
		}
	}
	if match == nil {
		c.abort(http.StatusNotFound)
		return
	}
	methods := strings.Fields(match.methods)
	allowed := map[string]bool{"OPTIONS": true}
	for _, m := range methods {
		allowed[m] = true
		if m == "GET" {
			allowed["HEAD"] = true
		}
	}
	method := c.r.Method
	if method == "HEAD" {
		method = "GET"
	}
	switch {
	case c.r.Method == "OPTIONS":
		c.status = http.StatusOK
		c.header.Set("Allow", allowHeader(allowed))
		c.header.Set("Content-Type", "text/html; charset=utf-8")
	case !allowed[method]:
		c.abort(http.StatusMethodNotAllowed)
		c.header.Set("Allow", allowHeader(allowed))
	default:
		match.view()
	}
}

func allowHeader(allowed map[string]bool) string {
	var out []string
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST"} {
		if allowed[m] {
			out = append(out, m)
		}
	}
	return strings.Join(out, ", ")
}

func (a *App) serveStatic(c *reqCtx, name string) {
	c.static = true
	// Errors here are still the static endpoint, which skips the dynamic
	// cache headers, as in Flask.
	if !fs.ValidPath(name) || path.Base(name) == "README.md" {
		c.abort(http.StatusNotFound)
		return
	}
	f, err := a.static.Open(name)
	if err != nil {
		c.abort(http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		c.abort(http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		c.abort(http.StatusInternalServerError)
		return
	}
	ctype := staticTypes[path.Ext(name)]
	if ctype == "" {
		ctype = mime.TypeByExtension(path.Ext(name))
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	c.write(http.StatusOK, ctype, data)
	c.header.Set("Cache-Control", "no-cache")
}

// staticTypes fixes the Content-Type of the panel's own static files.
// mime.TypeByExtension consults the registry on Windows, where .js is often
// application/javascript; Flask serves text/javascript on every platform.
var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
}

// loginRequired redirects to the login page while a password is set and
// the session is not logged in.
func (a *App) loginRequired(c *reqCtx, view func(*reqCtx)) {
	if a.auth.PasswordConfigured() && !c.sess.Authenticated() {
		c.redirect(urlLogin(c.r.URL.Path))
		return
	}
	view(c)
}

func (a *App) login(c *reqCtx) {
	if !a.auth.PasswordConfigured() {
		c.redirect("/")
		return
	}
	if c.r.Method == http.MethodPost {
		record := a.auth.Load()
		if record != nil && record.VerifyPassword(c.r.PostFormValue("password")) {
			c.sess.SetAuthenticated(true)
			c.redirect(auth.SafeNextURL(c.r.PostFormValue("next")))
			return
		}
		c.flash("Incorrect password.", "error")
	}
	next := c.r.URL.Query().Get("next")
	safe := ""
	if auth.SafeNextURL(next) == next {
		safe = next
	}
	c.render("login", map[string]any{"next": safe})
}

func (a *App) logout(c *reqCtx) {
	c.sess.SetAuthenticated(false)
	c.redirect("/")
}

func (a *App) setPassword(c *reqCtx) {
	if a.auth.PasswordConfigured() && !c.sess.Authenticated() {
		c.redirect(urlLogin("/set-password"))
		return
	}
	changing := a.auth.PasswordConfigured()
	if c.r.Method == http.MethodPost {
		password := c.r.PostFormValue("password")
		confirm := c.r.PostFormValue("password_confirm")
		record := a.auth.Load()
		switch {
		case changing && (record == nil || !record.VerifyPassword(c.r.PostFormValue("current_password"))):
			c.flash("Current password is incorrect.", "error")
		case utf8.RuneCountInString(password) < 8:
			c.flash("Password must be at least 8 characters.", "error")
		case password != confirm:
			c.flash("Passwords do not match.", "error")
		default:
			key, err := a.auth.SavePassword(password)
			if err != nil {
				a.log.Error("Saving the password failed", "err", err)
				c.abort(http.StatusInternalServerError)
				return
			}
			a.sessions.SetSecret(key)
			c.sess.SetAuthenticated(true)
			c.flash("Password saved.", "success")
			c.redirect("/")
			return
		}
	}
	c.render("set_password", map[string]any{"changing": changing})
}

func (a *App) discover(c *reqCtx) {
	c.json(map[string]any{"service": "kid-pc-monitor-panel", "version": int64(1), "reverse_port": int64(a.reversePort)})
}

func (a *App) index(c *reqCtx) {
	pcs, lastPoll, err := a.store.DashboardPCs()
	if err != nil {
		panic(err)
	}
	var lastPollAt any
	if lastPoll != nil {
		lastPollAt = pyval.ISOFormat(*lastPoll, true)
	}
	c.render("index", map[string]any{"pcs": pcs, "last_poll_at": lastPollAt})
}

func (a *App) control(c *reqCtx, target string) {
	ip, info, msg := a.fetchControlPCInfo(target)
	if info == nil {
		c.html(http.StatusNotFound, msg)
		return
	}
	updated, ok, err := a.store.PCPollUpdatedAt(ip)
	if err != nil {
		panic(err)
	}
	var updatedAt any
	if ok {
		updatedAt = pyval.ISOFormatSeconds(updated, true)
	}
	c.render("control", map[string]any{"ip": ip, "pc_info": info, "poll_updated_at": updatedAt})
}

func (a *App) pollMeta(c *reqCtx, target string) {
	ip, _, found := a.resolveControlTarget(target)
	if !found {
		c.abort(http.StatusNotFound)
		return
	}
	updated, ok, err := a.store.PCPollUpdatedAt(ip)
	if err != nil {
		panic(err)
	}
	var updatedAt any
	if ok {
		updatedAt = pyval.ISOFormatSeconds(updated, true)
	}
	c.json(map[string]any{"updated_at": updatedAt, "poll_interval_sec": int64(PollIntervalSec)})
}

func (a *App) stats(c *reqCtx, target string) {
	var ip string
	var info map[string]any
	if c.r.URL.Query().Get("source") == "poll" {
		ip, info, _ = a.fetchControlPCInfoCached(target)
	} else {
		ip, info, _ = a.fetchControlPCInfo(target)
	}
	if info == nil {
		c.abort(http.StatusNotFound)
		return
	}
	c.render("stats", map[string]any{"ip": ip, "pc_info": info})
}

func (a *App) logs(c *reqCtx, ip string) {
	var hostname any = "PC at " + ip
	scanPC, err := a.store.ScanPC(ip)
	if err != nil {
		panic(err)
	}
	if scanPC != nil {
		if h, ok := scanPC["hostname"]; ok {
			hostname = h
		}
	} else {
		snap, err := a.store.LatestSnapshotForPC("", ip, false)
		if err != nil {
			panic(err)
		}
		if snap != nil {
			if h, ok := snap.Payload["hostname"]; ok {
				hostname = h
			}
		}
	}
	logText, truncated, errorMessage := "", false, ""
	sessHost, _, live := a.session(ip)
	if live {
		hostname = pyval.Or(sessHost, hostname)
		result, err := a.reverse.GetLogs(ip)
		if err != nil {
			errorMessage = format.FormatAgentConnectionError(errorText(err))
		} else {
			truncated = result.Truncated
			logText = strings.Join(result.Lines, "\n")
			if logText == "" {
				logText = "(log file is empty)"
			}
		}
	} else {
		errorMessage = "PC is not connected. Wait for the agent to reconnect, then open logs again."
	}
	c.render("logs", map[string]any{
		"ip": ip, "hostname": hostname, "log_text": logText, "truncated": truncated, "error_message": errorMessage,
	})
}

func (a *App) dailySettings(c *reqCtx, ip string) {
	_, info, msg := a.fetchControlPCInfo(ip)
	if info == nil {
		c.flash(msg, "error")
		c.redirect("/")
		return
	}
	if pyval.Truthy(info["connection_error"]) {
		c.flash(pyval.Str(pyval.Or(info["connection_error"], "PC unreachable")), "error")
		c.redirect("/")
		return
	}
	c.render("daily_settings", map[string]any{"ip": ip, "pc_info": info})
}

func (a *App) usage(c *reqCtx, username string) {
	groups, err := a.store.UsageHistoryForUser(username, 7)
	if err != nil {
		panic(err)
	}
	c.render("usage_history", map[string]any{"username": username, "pc_groups": groups})
}

func (a *App) action(c *reqCtx) {
	payload := map[string]any{}
	if isJSON(c.r.Header.Get("Content-Type")) {
		if raw, err := io.ReadAll(c.r.Body); err == nil {
			if v, err := pyval.DecodeJSON(raw); err == nil {
				if m, ok := v.(map[string]any); ok {
					payload = m
				}
			}
		}
	}
	ip, actionName := payload["ip"], payload["action"]
	if !pyval.Truthy(ip) || !pyval.Truthy(actionName) {
		c.json(map[string]any{"success": false, "response": "Missing ip or action"})
		return
	}
	ok, text := a.performControlAction(pyval.Str(ip), pyval.Str(actionName), payload)
	c.json(map[string]any{"success": ok, "response": text})
}

// isJSON is werkzeug's Request.is_json.
func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// errorText is str(exc) as Python shows it: a protocol error's message.
func errorText(err error) string { return reverse.ErrorText(err) }

// ---------------------------------------------------------------------------
// PC lookups (web_panel._fetch_control_pc_info and friends)
// ---------------------------------------------------------------------------

func unknownPC(target string) string {
	return "No connected PC found for " + target + ". PCs appear here after the agent connects to this panel."
}

func (a *App) session(ip string) (string, map[string]any, bool) {
	if a.reverse == nil {
		return "", nil, false
	}
	return a.reverse.Session(ip)
}

func (a *App) performControlAction(ip, action string, payload map[string]any) (bool, string) {
	if a.reverse != nil {
		if ok, text, found := a.reverse.PerformAction(ip, action, payload); found {
			return ok, text
		}
	}
	return false, "PC is not connected. Wait for the agent to reconnect, then try again."
}

// resolveControlTarget maps an IP or a tracked hostname to an IP and the
// requested hostname ("" for an IP).
func (a *App) resolveControlTarget(target string) (ip, hostname string, found bool) {
	if _, err := netip.ParseAddr(target); err == nil {
		return target, "", true
	}
	pc, err := a.store.ScanPCByHostname(target)
	if err != nil {
		panic(err)
	}
	if pc == nil || !pyval.Truthy(pc["ip"]) {
		return "", "", false
	}
	return pyval.Str(pc["ip"]), pyval.Str(pyval.Or(pc["hostname"], target)), true
}

// snapshotLookupHostname prefers a stable agent hostname so snapshots
// survive DHCP IP changes.
func (a *App) snapshotLookupHostname(info map[string]any, ip string) any {
	hostname := info["hostname"]
	if pyval.Truthy(hostname) && hostname != "PC at "+ip {
		return hostname
	}
	pc, err := a.store.ScanPC(ip)
	if err != nil {
		panic(err)
	}
	if pc != nil && pyval.Truthy(pc["hostname"]) {
		return pyval.Str(pc["hostname"])
	}
	return hostname
}

func lookupText(v any) string {
	if !pyval.Truthy(v) {
		return ""
	}
	return pyval.Str(v)
}

func (a *App) applyPCSnapshot(info map[string]any, ip string) map[string]any {
	if pyval.Truthy(getd(info, "reachable", true)) && !pyval.Truthy(info["connection_error"]) {
		return info
	}
	snap, err := a.store.LatestPanelSnapshotForPC(lookupText(a.snapshotLookupHostname(info, ip)), ip)
	if err != nil {
		panic(err)
	}
	if snap == nil {
		return info
	}
	panel := merge(snap.Payload, map[string]any{
		"reachable": false, "is_snapshot": true, "snapshot_recorded_at": snap.RecordedAt, "ip": ip,
	})
	delete(panel, "connection_error")
	delete(panel, "agent_not_running")
	if pyval.Truthy(info["agent_not_running"]) {
		panel["agent_not_running"] = true
	}
	return panel
}

// fetchControlPCInfo returns the PC's live info from its reverse session,
// else its registry entry with the latest snapshot; info is nil (with the
// message to show) for an unknown PC.
func (a *App) fetchControlPCInfo(target string) (ip string, info map[string]any, msg string) {
	ip, requested, found := a.resolveControlTarget(target)
	if !found {
		return "", nil, unknownPC(target)
	}
	if host, settings, ok := a.session(ip); ok && len(settings) > 0 {
		live, err := format.SettingsToPCInfo(settings, ip, host)
		if err != nil {
			panic(err)
		}
		live["ip"] = ip
		live["reachable"] = true
		return ip, live, ""
	}
	entry, err := a.store.ScanPC(ip)
	if err != nil {
		panic(err)
	}
	if entry == nil {
		return "", nil, unknownPC(target)
	}
	base := map[string]any{"hostname": pyval.Or(pyval.Or(
		a.snapshotLookupHostname(map[string]any{"hostname": pyval.Or(pyval.Or(nonEmpty(requested), entry["hostname"]), "PC at "+ip)}, ip),
		entry["hostname"]), "PC at "+ip)}
	info = merge(merge(base, entry), map[string]any{"ip": ip, "reachable": false})
	return ip, a.applyPCSnapshot(info, ip), ""
}

// fetchControlPCInfoCached is fetchControlPCInfo from the registry only.
func (a *App) fetchControlPCInfoCached(target string) (ip string, info map[string]any, msg string) {
	ip, requested, found := a.resolveControlTarget(target)
	if !found {
		return "", nil, unknownPC(target)
	}
	entry, err := a.store.ScanPC(ip)
	if err != nil {
		panic(err)
	}
	if entry == nil {
		return "", nil, unknownPC(target)
	}
	info = merge(entry, map[string]any{"ip": ip})
	if !pyval.Truthy(getd(info, "reachable", true)) || pyval.Truthy(info["connection_error"]) {
		base := map[string]any{"hostname": pyval.Or(pyval.Or(
			a.snapshotLookupHostname(map[string]any{"hostname": pyval.Or(pyval.Or(nonEmpty(requested), info["hostname"]), "PC at "+ip)}, ip),
			info["hostname"]), "PC at "+ip)}
		info = a.applyPCSnapshot(merge(base, info), ip)
	}
	return ip, info, ""
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func getd(m map[string]any, key string, fallback any) any {
	if v, ok := m[key]; ok {
		return v
	}
	return fallback
}

func merge(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
