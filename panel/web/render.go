package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"reflect"
	"strings"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pages are the full-page templates, each rendered through "base".
var pages = []string{"index", "control", "login", "set_password", "daily_settings", "logs", "usage_history"}

// view is what every template renders: the request's context
// (web_panel.inject_panel_context) plus the page's own values in D.
type view struct {
	c *reqCtx
	D map[string]any
}

// CSRFToken is csrf_token(): the session's token, created on first use.
func (v *view) CSRFToken() string { return v.c.sess.CSRFToken() }

// Flashes is get_flashed_messages(with_categories=true): popped from the
// session on the first call, the same list on later calls.
func (v *view) Flashes() []flashMsg { return v.c.flashes() }

// PasswordProtected is password_is_configured().
func (v *view) PasswordProtected() bool { return v.c.app.auth.PasswordConfigured() }

// PanelAuth is session.get("panel_authenticated").
func (v *view) PanelAuth() bool { return v.c.sess.Authenticated() }

// PanelUsername is PANEL_USERNAME.
func (v *view) PanelUsername() string { return PanelUsername }

// RequestPath is request.path.
func (v *view) RequestPath() string { return v.c.r.URL.Path }

// Recorded is format_snapshot_recorded_at at the panel's current time.
func (v *view) Recorded(recordedAt any) string {
	s, _ := recordedAt.(string)
	if !pyval.Truthy(recordedAt) {
		return ""
	}
	return format.FormatSnapshotRecordedAt(s, v.c.app.now())
}

// RecordedDay names the day a snapshot was recorded on ("Today",
// "Yesterday", "Nov 4"), or "" when there is no usable timestamp.
func (v *view) RecordedDay(recordedAt any) string {
	s, _ := recordedAt.(string)
	if !pyval.Truthy(recordedAt) {
		return ""
	}
	return format.SnapshotDayLabel(s, v.c.app.now())
}

type flashMsg struct {
	Category string
	Message  string
}

// The helpers below give templates Python/Jinja semantics on dynamically
// typed PC-info dicts.
var funcs = template.FuncMap{
	// get is dict.get(key): nil for a missing key.
	"get": func(m any, key string) any {
		if d, ok := m.(map[string]any); ok {
			return d[key]
		}
		return nil
	},
	// getd is dict.get(key, default).
	"getd": func(m any, key string, fallback any) any {
		if d, ok := m.(map[string]any); ok {
			if v, present := d[key]; present {
				return v
			}
		}
		return fallback
	},
	// show is Jinja's {{ d.key }}: "" for a missing key, else str(value)
	// (so None prints "None", 60.0 prints "60.0").
	"show": func(m any, key string) string {
		if d, ok := m.(map[string]any); ok {
			if v, present := d[key]; present {
				return pyval.Str(v)
			}
		}
		return ""
	},
	"str":     pyval.Str,
	"notnone": func(v any) bool { return v != nil },
	"pyeq":    pyEq,
	"fmin":    format.FormatMinutesDuration,
	"fsec":    format.FormatSecondsDuration,
	"fdate": func(day any) string {
		s, ok := day.(string)
		if !ok {
			return pyval.Str(day)
		}
		return format.FormatUsageDate(s)
	},
	"remaining": format.RemainingMinutes,
	// maxzero is [v, 0] | max: v unless it is negative.
	"maxzero": func(v any) any {
		if f, ok := pyval.Number(v); ok && f < 0 {
			return int64(0)
		}
		return v
	},
	// gt0 is v > 0 for a number.
	"gt0": func(v any) bool {
		f, ok := pyval.Number(v)
		return ok && f > 0
	},
	"meter":    meter,
	"rowClass": rowClass,

	"urlIndex":       func() string { return "/" },
	"urlLogout":      func() string { return "/logout" },
	"urlSetPassword": func() string { return "/set-password" },
	"urlStatic":      func(file string) string { return "/static/" + quotePath(file) },
	"urlControl":     func(target any) string { return "/control/" + quotePath(pyval.Str(target)) },
	"urlDaily":       func(ip any) string { return "/daily_settings/" + quotePath(pyval.Str(ip)) },
	"urlLogs":        func(ip any) string { return "/logs/" + quotePath(pyval.Str(ip)) },
	"urlUsage":       func(user any) string { return "/usage/" + quotePath(pyval.Str(user)) },
	"urlLogin":       urlLogin,
}

func urlLogin(next string) string {
	if next == "" {
		return "/login"
	}
	return "/login?next=" + quoteQuery(next)
}

func pyEq(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	fa, aNum := pyval.Number(a)
	fb, bNum := pyval.Number(b)
	if aNum && bNum {
		return fa == fb
	}
	if reflect.TypeOf(a).Comparable() && reflect.TypeOf(b).Comparable() {
		return a == b
	}
	return false
}

type meterView struct {
	Class string
	Now   int64
	Width string
}

// meter is the allowance bar: used_pct = min(used / 60 / limit * 100, 100),
// shown as "%.1f" and as int(round(used_pct)).
func meter(used, limit any) meterView {
	u, _ := pyval.Number(used)
	l, _ := pyval.Number(limit)
	pct := u / 60 / l * 100
	if pct > 100 {
		pct = 100
	}
	m := meterView{Now: int64(math.RoundToEven(pct)), Width: fmt.Sprintf("%.1f", pct)}
	switch {
	case pct >= 100:
		m.Class = " over"
	case pct >= 85:
		m.Class = " near"
	}
	return m
}

// rowClass is ['is-today' if loop.first, 'no-data' if day.no_data] | select | join(' ').
func rowClass(first bool, noData any) string {
	var parts []string
	if first {
		parts = append(parts, "is-today")
	}
	if pyval.Truthy(noData) {
		parts = append(parts, "no-data")
	}
	return strings.Join(parts, " ")
}

// werkzeug's url_for quoting: path parts keep RFC 3986 unreserved characters
// and !$&'()*+,/:;=@; query values also keep ? but encode & = + and turn a
// space into "+". Everything else is %XX of its UTF-8 bytes.
const (
	pathSafe  = "!$&'()*+,/:;=@"
	querySafe = "!$'()*,/:;?@"
)

func quoteWith(s, safe string, plusSpace bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		case c == ' ' && plusSpace:
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func quotePath(s string) string  { return quoteWith(s, pathSafe, false) }
func quoteQuery(s string) string { return quoteWith(s, querySafe, true) }

// templates holds one parsed set per page plus the bare stats fragment.
type templates struct {
	pages map[string]*template.Template
	stats *template.Template
}

func loadTemplates() (*templates, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/base.html", "templates/control_today_stats.html")
	if err != nil {
		return nil, err
	}
	t := &templates{pages: map[string]*template.Template{}, stats: base}
	for _, name := range pages {
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := clone.ParseFS(templateFS, "templates/"+name+".html"); err != nil {
			return nil, err
		}
		t.pages[name] = clone
	}
	return t, nil
}

func (t *templates) render(page string, v *view) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if page == "stats" {
		err = t.stats.ExecuteTemplate(&buf, "stats", v)
	} else {
		err = t.pages[page].ExecuteTemplate(&buf, "base", v)
	}
	return buf.Bytes(), err
}

func staticRoot() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
