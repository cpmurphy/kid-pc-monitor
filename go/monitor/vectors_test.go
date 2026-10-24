package monitor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"kidpcmonitor/policy"
	"kidpcmonitor/state"
)

// The golden vectors are generated from the Python implementation by
// tests/monitor_vectors_gen.py. Each scenario is replayed here against a fake
// clock and platform; after every step the platform calls, log lines, changed
// state files and in-memory state must match.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "monitor", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return norm(v).(obj)
}

// norm turns json.Number into int64 (or float64 when written as a fraction).
func norm(v any) any {
	switch x := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, _ := x.Float64()
			return f
		}
		n, err := x.Int64()
		if err != nil {
			panic(err)
		}
		return n
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = norm(x[i])
		}
		return out
	case map[string]any:
		out := make(obj, len(x))
		for k, e := range x {
			out[k] = norm(e)
		}
		return out
	}
	return v
}

// roundTrip puts a Go value through JSON so it has the same shape as a vector.
func roundTrip(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return norm(out)
}

// equal is reflect.DeepEqual except that numbers compare by value, so 0 == 0.0.
func equal(a, b any) bool {
	fa, aNum := asFloat(a)
	fb, bNum := asFloat(b)
	if aNum || bNum {
		return aNum && bNum && fa == fb
	}
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case obj:
		y, ok := b.(obj)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, e := range x {
			f, ok := y[k]
			if !ok || !equal(e, f) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// --- fakes ------------------------------------------------------------------

var errBoom = errors.New("boom")

type fakePlatform struct {
	locked, active, lockSetsLocked bool
	fail                           map[string]bool
	events                         []any
}

func newFakePlatform(spec obj) *fakePlatform {
	p := &fakePlatform{active: true, lockSetsLocked: true, fail: map[string]bool{}}
	p.configure(spec)
	return p
}

func (p *fakePlatform) configure(spec obj) {
	if v, ok := spec["locked"].(bool); ok {
		p.locked = v
	}
	if v, ok := spec["active"].(bool); ok {
		p.active = v
	}
	if v, ok := spec["lock_sets_locked"].(bool); ok {
		p.lockSetsLocked = v
	}
	if v, ok := spec["fail"].([]any); ok {
		p.fail = map[string]bool{}
		for _, name := range v {
			p.fail[name.(string)] = true
		}
	}
}

func (p *fakePlatform) check(name string) error {
	if p.fail[name] {
		return errBoom
	}
	return nil
}

func (p *fakePlatform) event(args ...any) { p.events = append(p.events, args) }

func (p *fakePlatform) CheckSessionLocked() (bool, error) {
	return p.locked, p.check("check_session_locked")
}

func (p *fakePlatform) SessionIsActive() (bool, error) {
	return p.active && !p.locked, p.check("session_is_active")
}

func (p *fakePlatform) LockWorkstation() error {
	p.event("lock")
	if err := p.check("lock_workstation"); err != nil {
		return err
	}
	if p.lockSetsLocked {
		p.locked = true
	}
	return nil
}

func (p *fakePlatform) Shutdown(seconds int64) error {
	p.event("shutdown", seconds)
	return p.check("shutdown")
}

func (p *fakePlatform) CancelShutdown() error {
	p.event("cancel_shutdown")
	return p.check("cancel_shutdown")
}

func (p *fakePlatform) ShowMessage(message, title string) error {
	p.event("message", title, message)
	return p.check("show_message")
}

func (p *fakePlatform) Hostname() string { return "test-pc" }

// logCapture is a slog.Handler that records [level, message].
type logCapture struct {
	prefixOnly []string
	records    *[]any
}

func (h logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h logCapture) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h logCapture) WithGroup(string) slog.Handler            { return h }
func (h logCapture) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message
	for _, prefix := range h.prefixOnly {
		if strings.HasPrefix(msg, prefix) {
			msg = prefix
			break
		}
	}
	*h.records = append(*h.records, []any{r.Level.String(), msg})
	return nil
}

type clockState struct{ now time.Time }

func parseISO(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := state.ParseISODatetime(s)
	if err != nil {
		t.Fatalf("bad time %q: %v", s, err)
	}
	return at
}

// --- the scenario runner ----------------------------------------------------

var stateFiles = []string{"daily_settings.json", "state.json"}

func readFiles(t *testing.T, dir string) obj {
	t.Helper()
	out := obj{}
	for _, name := range stateFiles {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			out[name] = nil
			continue
		}
		var doc any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			out[name] = obj{"__text__": string(raw)}
			continue
		}
		out[name] = norm(doc)
	}
	return out
}

func isoOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return state.FormatISO(*t)
}

func hhmmOrNil(t *policy.TimeOfDay) any {
	if t == nil {
		return nil
	}
	return t.String()
}

func reasonOrNil(active bool, reason string) any {
	if !active {
		return nil
	}
	return reason
}

// view is the control's in-memory state, shaped like the generator's view().
func view(t *testing.T, c *Control) obj {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	locked, lockReason := c.currentlyInLockWindow()
	enfActive, enfReason := c.enforcementLockState()
	var remaining any
	if m, ok := c.timeRemaining(); ok {
		remaining = m
	}
	var allowance any
	if c.daily.Allowance != nil {
		allowance = *c.daily.Allowance
	}
	var lastReason any
	if c.lastLogReason != nil {
		lastReason = *c.lastLogReason
	}
	failures := []string{}
	for k := range c.failures {
		failures = append(failures, k)
	}
	sort.Strings(failures)
	sent := c.warningsSentSorted()
	return roundTrip(t, obj{
		"bed_time":            hhmmOrNil(c.daily.BedTime),
		"wake_time":           c.daily.WakeTime.String(),
		"allowance":           allowance,
		"timestamp":           state.FormatISO(c.runtime.Timestamp),
		"accumulated_seconds": c.runtime.AccumulatedSeconds,
		"manual_lock_active":  c.runtime.ManualLockActive,
		"extension_seconds":   c.runtime.CumulativeExtensionSeconds,
		"warnings_sent":       sent,
		"warnings_date":       c.warningsDate.String(),
		"last_tick_at":        isoOrNil(c.lastTickAt),
		"last_persist_at":     isoOrNil(c.lastPersistAt),
		"is_locked":           c.isLocked,
		"last_logged_reason":  lastReason,
		"state_load_failed":   c.stateLoadFail,
		"step_errors":         failures,
		"time_remaining":      remaining,
		"lock_window":         []any{locked, lockReason},
		"enforcement":         []any{enfActive, reasonOrNil(enfActive, enfReason)},
	}).(obj)
}

func argInt(args []any, i int) int64 { return args[i].(int64) }

func argIntOrNil(args []any, i int) *int64 {
	if args[i] == nil {
		return nil
	}
	v := args[i].(int64)
	return &v
}

// opResult is what an op returned: a value, or a failure.
type opResult struct {
	value any
	err   error
}

func runCall(c *Control, method string, args []any) error {
	switch method {
	case "set_bed_time":
		c.SetBedTime(int(argInt(args, 0)), int(argInt(args, 1)))
	case "clear_bed_time":
		c.ClearBedTime()
	case "set_wake_time":
		c.SetWakeTime(int(argInt(args, 0)), int(argInt(args, 1)))
	case "set_daily_allowance":
		c.SetDailyAllowance(argIntOrNil(args, 0))
	case "extend_time":
		c.ExtendTime(argInt(args, 0))
	case "clear_extensions":
		c.ClearExtensions()
	case "clear_warnings":
		c.ClearWarnings()
	case "engage_manual_lock":
		c.EngageManualLock()
	case "clear_manual_lock":
		c.ClearManualLock()
	case "send_parent_message":
		return c.SendParentMessage(args[0].(string))
	case "shutdown_pc":
		seconds := int64(60)
		if len(args) > 0 {
			seconds = argInt(args, 0)
		}
		c.ShutdownPC(seconds)
	case "cancel_shutdown":
		return c.CancelShutdown()
	case "save_state":
		c.SaveState()
	case "load_state":
		c.LoadState()
	case "lock_pc":
		c.LockPC()
	default:
		panic("unknown call " + method)
	}
	return nil
}

func runRead(c *Control, what string) any {
	switch what {
	case "time_remaining":
		if m, ok := c.TimeRemainingMinutes(); ok {
			return m
		}
		return nil
	case "access_status":
		return c.AccessStatus()
	case "enforcement_lock_state":
		active, reason := c.EnforcementLockState()
		return []any{active, reasonOrNil(active, reason)}
	case "lock_window":
		c.mu.Lock()
		defer c.mu.Unlock()
		locked, reason := c.currentlyInLockWindow()
		return []any{locked, reason}
	case "check_if_locked":
		return c.ScreenLocked()
	case "session_is_active":
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.sessionIsActive()
	}
	panic("unknown read " + what)
}

func runOp(t *testing.T, op obj, c *Control, p *fakePlatform, clock *clockState, dir string) opResult {
	t.Helper()
	switch kind := op["op"].(string); kind {
	case "advance":
		clock.now = clock.now.Add(time.Duration(op["us"].(int64)) * time.Microsecond)
	case "set_clock":
		clock.now = parseISO(t, op["at"].(string))
	case "platform":
		p.configure(op)
	case "tick":
		c.Tick()
	case "warnings":
		return opResult{err: c.CheckAndSendWarnings()}
	case "step":
		c.Step()
	case "observe":
		c.ObserveLockState()
	case "call":
		args, _ := op["args"].([]any)
		return opResult{err: runCall(c, op["method"].(string), args)}
	case "read":
		return opResult{value: runRead(c, op["what"].(string))}
	case "set_accumulated":
		c.mu.Lock()
		c.runtime.AccumulatedSeconds, _ = asFloat(op["seconds"])
		c.mu.Unlock()
	case "write_file":
		return opResult{err: os.WriteFile(filepath.Join(dir, op["name"].(string)), []byte(op["text"].(string)), 0o644)}
	case "delete_file":
		if err := os.Remove(filepath.Join(dir, op["name"].(string))); err != nil && !os.IsNotExist(err) {
			return opResult{err: err}
		}
	case "mkdir":
		return opResult{err: os.Mkdir(filepath.Join(dir, op["name"].(string)), 0o755)}
	case "rmdir":
		return opResult{err: os.Remove(filepath.Join(dir, op["name"].(string)))}
	case "write_log":
		raw, err := hex.DecodeString(op["hex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		return opResult{err: os.WriteFile(c.AgentLogPath(), raw, 0o644)}
	case "read_tail":
		lines, truncated, err := c.ReadLogTail(op["tail"].(int64))
		if err != nil {
			return opResult{err: err}
		}
		out := make([]any, len(lines))
		for i, l := range lines {
			out[i] = l
		}
		return opResult{value: obj{"lines": out, "truncated": truncated}}
	default:
		t.Fatalf("unknown op %q", kind)
	}
	return opResult{}
}

func applyDelta(full, delta obj) {
	for k, v := range delta {
		full[k] = v
	}
}

func diffFiles(prev, now obj) obj {
	changed := obj{}
	for k, v := range now {
		if !equal(v, prev[k]) {
			changed[k] = v
		}
	}
	return changed
}

func TestVectors(t *testing.T) {
	vectors := loadVectors(t)
	var prefixOnly []string
	for _, p := range vectors["log_prefix_only"].([]any) {
		prefixOnly = append(prefixOnly, p.(string))
	}
	scenarios := vectors["scenarios"].([]any)
	if len(scenarios) < 100 {
		t.Fatalf("only %d scenarios", len(scenarios))
	}
	for _, s := range scenarios {
		scenario := s.(obj)
		t.Run(scenario["name"].(string), func(t *testing.T) {
			runScenario(t, scenario, prefixOnly)
		})
	}
}

func runScenario(t *testing.T, scenario obj, prefixOnly []string) {
	setup := scenario["setup"].(obj)
	dir := t.TempDir()
	if files, ok := setup["files"].(obj); ok {
		for name, text := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(text.(string)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	clock := &clockState{now: parseISO(t, setup["now"].(string))}
	spec, _ := setup["platform"].(obj)
	plat := newFakePlatform(spec)
	var records []any
	logger := slog.New(logCapture{prefixOnly: prefixOnly, records: &records})
	toStrings := func(key string) []string {
		var out []string
		list, _ := setup[key].([]any)
		for _, v := range list {
			out = append(out, v.(string))
		}
		return out
	}
	user := "kid"
	if u, ok := setup["user"].(string); ok {
		user = u
	}
	c, err := New(Config{
		Platform:       plat,
		MonitoredUsers: toStrings("monitored"),
		ExemptUsers:    toStrings("exempt"),
		CurrentUser:    user,
		DataDir:        dir,
		Clock:          func() time.Time { return clock.now },
		Logger:         logger,
		StateLogger:    slog.New(slog.NewTextHandler(discard{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	takeLogs := func() any {
		out := records
		records = nil
		if out == nil {
			out = []any{}
		}
		return out
	}
	takeEvents := func() any {
		out := plat.events
		plat.events = nil
		if out == nil {
			out = []any{}
		}
		return out
	}

	init := scenario["init"].(obj)
	compare(t, "init logs", takeLogs(), init["logs"])
	compare(t, "init events", takeEvents(), init["events"])
	fullView := view(t, c)
	compare(t, "init view", fullView, init["view"])
	filesSeen := readFiles(t, dir)
	compare(t, "init files", filesSeen, init["files"])

	ops := scenario["ops"].([]any)
	steps := scenario["steps"].([]any)
	for i, raw := range ops {
		op := raw.(obj)
		want := steps[i].(obj)
		label := fmt.Sprintf("step %d %s", i, opLabel(op))

		result := runOp(t, op, c, plat, clock, dir)

		wantResult, hasResult := want["result"]
		switch {
		case hasResult && wantResult != nil && isRaised(wantResult):
			if result.err == nil {
				t.Errorf("%s: expected a failure, got none", label)
			}
		case result.err != nil:
			t.Errorf("%s: unexpected error: %v", label, result.err)
		default:
			compare(t, label+" result", result.value, wantResult)
		}
		compare(t, label+" events", takeEvents(), want["events"])
		compare(t, label+" logs", takeLogs(), want["logs"])

		filesNow := readFiles(t, dir)
		compare(t, label+" files", diffFiles(filesSeen, filesNow), want["files"])
		filesSeen = filesNow

		applyDelta(fullView, want["view"].(obj))
		compare(t, label+" view", view(t, c), fullView)
		if t.Failed() {
			t.Fatalf("stopping after the first failing step (%s)", label)
		}
	}
}

func isRaised(v any) bool {
	m, ok := v.(obj)
	if !ok {
		return false
	}
	_, raised := m["raised"]
	return raised
}

func opLabel(op obj) string {
	raw, _ := json.Marshal(op)
	if len(raw) > 90 {
		raw = append(raw[:90], "..."...)
	}
	return string(raw)
}

func compare(t *testing.T, what string, got, want any) {
	t.Helper()
	got = roundTrip(t, got)
	if want == nil {
		if got != nil {
			t.Errorf("%s:\n got  %v\n want nothing", what, show(got))
		}
		return
	}
	if !equal(got, want) {
		t.Errorf("%s:\n got  %s\n want %s", what, show(got), show(want))
	}
}

func show(v any) string {
	raw, _ := json.Marshal(v)
	if len(raw) > 600 {
		return string(raw[:600]) + "..."
	}
	return string(raw)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
