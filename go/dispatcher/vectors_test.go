package dispatcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kidpcmonitor/policy"
	"kidpcmonitor/protocol"
)

// The golden vectors are generated from the Python implementation by
// tests/dispatcher_vectors_gen.py: each case is one request against a fake
// control, with the response and the calls the dispatcher made.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dispatcher", "vectors.json"))
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

// canon round-trips v through JSON so Go values compare with decoded vectors.
func canon(t *testing.T, v any) any {
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

func nodesToJSON(nodes []protocol.Node) []any {
	out := make([]any, 0, len(nodes))
	for _, n := range nodes {
		m := obj{"name": n.Name, "args": append([]any{}, n.Args...)}
		if len(n.Children) > 0 {
			m["children"] = nodesToJSON(n.Children)
		}
		out = append(out, m)
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

func expandLines(spec any) []string {
	if list, ok := spec.([]any); ok {
		out := make([]string, len(list))
		for i, l := range list {
			out[i] = l.(string)
		}
		return out
	}
	m := spec.(obj)
	count := int(m["count"].(int64))
	var out []string
	switch m["gen"] {
	case "plain":
		for i := 0; i < count; i++ {
			out = append(out, fmt.Sprintf("[2026-05-31 12:00:%02d] INFO kid_pc_monitor: line %d with some text", i%60, i))
		}
	case "wide":
		for i := 0; i < count; i++ {
			out = append(out, strings.Repeat("é", 300)+fmt.Sprint(i))
		}
	case "quoted":
		for i := 0; i < count; i++ {
			out = append(out, fmt.Sprintf("\"%d\" \\ \t", i))
		}
	case "boundary":
		for i := 0; i < count; i++ {
			out = append(out, fmt.Sprintf("line %05d ", i)+strings.Repeat("x", 28))
		}
		out = append(out, strings.Repeat("y", int(m["pad"].(int64))))
	default:
		panic("unknown log generator")
	}
	return out
}

// fake is the Go twin of FakeControl in tests/dispatcher_vectors_gen.py.
type fake struct {
	st        obj
	calls     [][]any
	allowance *int64
	bed       *policy.TimeOfDay
	wake      policy.TimeOfDay
	manual    bool
	extension int64
	logLines  []string
}

func parseTOD(t *testing.T, v any) *policy.TimeOfDay {
	if v == nil {
		return nil
	}
	tod, err := policy.ParseTimeHHMM(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return &tod
}

func newFake(t *testing.T, st obj) *fake {
	f := &fake{st: st, bed: parseTOD(t, st["bed_time"]), manual: st["manual_lock"].(bool),
		extension: st["extension_seconds"].(int64), logLines: expandLines(st["log_lines"])}
	f.wake = *parseTOD(t, st["wake_time"])
	if a, ok := st["allowance"].(int64); ok {
		f.allowance = &a
	}
	return f
}

func (f *fake) record(args ...any) { f.calls = append(f.calls, args) }

func (f *fake) Hostname() string                  { return str(f.st["hostname"]) }
func (f *fake) CurrentUser() string               { return str(f.st["current_user"]) }
func (f *fake) ScreenLocked() bool                { return f.st["screen_locked"].(bool) }
func (f *fake) DailyAllowance() *int64            { return f.allowance }
func (f *fake) BedTime() *policy.TimeOfDay        { return f.bed }
func (f *fake) WakeTime() policy.TimeOfDay        { return f.wake }
func (f *fake) ManualLockActive() bool            { return f.manual }
func (f *fake) CumulativeExtensionSeconds() int64 { return f.extension }
func (f *fake) AccumulatedSeconds() float64 {
	switch x := f.st["accumulated_seconds"].(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	}
	return 0
}
func (f *fake) TimeRemainingMinutes() (float64, bool) {
	switch x := f.st["time_remaining"].(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	}
	return 0, false
}
func (f *fake) EnforcementLockState() (bool, string) {
	pair := f.st["enforcement"].([]any)
	reason, _ := pair[1].(string)
	return pair[0].(bool), reason
}
func (f *fake) AccessStatus() string { return str(f.st["access_status"]) }
func (f *fake) AgentLogPath() string { return str(f.st["log_path"]) }
func (f *fake) ReadLogTail(tail int64) ([]string, bool, error) {
	f.record("read_log_tail", tail)
	if msg, ok := f.st["log_error"].(string); ok {
		return nil, false, errors.New(msg)
	}
	lines := f.logLines
	if int64(len(lines)) > tail {
		lines = lines[int64(len(lines))-tail:]
	}
	return lines, f.st["log_truncated"].(bool) || int64(len(f.logLines)) > tail, nil
}

func (f *fake) SetDailyAllowance(m *int64) {
	if m == nil {
		f.record("set_daily_allowance", nil)
	} else {
		f.record("set_daily_allowance", *m)
	}
	f.allowance = m
}
func (f *fake) SetBedTime(h, m int) {
	f.record("set_bed_time", int64(h), int64(m))
	f.bed = &policy.TimeOfDay{Hour: h, Minute: m}
}
func (f *fake) ClearBedTime()  { f.record("clear_bed_time"); f.bed = nil }
func (f *fake) ClearWarnings() { f.record("clear_warnings") }
func (f *fake) SetWakeTime(h, m int) {
	f.record("set_wake_time", int64(h), int64(m))
	f.wake = policy.TimeOfDay{Hour: h, Minute: m}
}
func (f *fake) EngageManualLock() { f.record("engage_manual_lock"); f.manual = true }
func (f *fake) ClearManualLock()  { f.record("clear_manual_lock"); f.manual = false }
func (f *fake) ClearExtensions()  { f.record("clear_extensions"); f.extension = 0 }
func (f *fake) ExtendTime(m int64) {
	f.record("extend_time", m)
	f.extension += m * 60
	f.manual = false
}
func (f *fake) SendParentMessage(text string) error {
	f.record("send_parent_message", text)
	return nil
}
func (f *fake) ShutdownPC(seconds int64) { f.record("shutdown_pc", seconds) }
func (f *fake) SaveState()               { f.record("save_state") }

func buildRequest(c obj) *protocol.Request {
	r := c["request"].(obj)
	req := &protocol.Request{Version: protocol.ProtocolVersion, Action: str(r["action"]), Val: r["val"]}
	req.ID = protocol.Ptr("r1")
	if v, present := r["id"]; present {
		req.ID = nil
		if s, ok := v.(string); ok {
			req.ID = protocol.Ptr(s)
		}
	}
	if s, ok := r["var"].(string); ok {
		req.Var = protocol.Ptr(s)
	}
	req.Name = protocol.Ptr("kid-pc")
	if n, ok := r["tail"].(int64); ok {
		req.Tail = &n
	}
	return req
}

func TestVectorConstants(t *testing.T) {
	c := loadVectors(t)["constants"].(obj)
	for name, got := range map[string]int64{
		"min_daily_limit": protocol.MinDailyLimit, "max_daily_limit": protocol.MaxDailyLimit,
		"default_shutdown_seconds": protocol.DefaultShutdownSeconds,
		"default_log_tail_lines":   protocol.DefaultLogTailLines, "max_frame_bytes": protocol.MaxFrameBytes,
	} {
		if c[name] != got {
			t.Errorf("%s = %v in Python, %d in Go", name, c[name], got)
		}
	}
	for name, set := range map[string]map[string]bool{
		"writable_variables": protocol.WritableVariables, "clearable_variables": protocol.ClearableVariables,
	} {
		want := map[string]bool{}
		for _, v := range c[name].([]any) {
			want[v.(string)] = true
		}
		if !reflect.DeepEqual(want, set) {
			t.Errorf("%s: Python %v, Go %v", name, want, set)
		}
	}
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	defaults := v["default_state"].(obj)
	list := v["cases"].([]any)
	if len(list) == 0 {
		t.Fatal("no cases")
	}
	for _, raw := range list {
		c := raw.(obj)
		t.Run(str(c["name"]), func(t *testing.T) {
			state := obj{}
			for k, val := range defaults {
				state[k] = val
			}
			for k, val := range c["state"].(obj) {
				state[k] = val
			}
			f := newFake(t, state)
			content, err := Dispatch(f, buildRequest(c))

			if want, isErr := c["error"].(obj); isErr {
				var pe *protocol.ProtocolError
				if !errors.As(err, &pe) {
					t.Fatalf("got err=%v content=%v, want error %v", err, content, want)
				}
				var reqID any
				if pe.ReqID != nil {
					reqID = *pe.ReqID
				}
				if pe.Code != want["code"] || pe.Message != want["message"] || reqID != want["req_id"] {
					t.Errorf("error = {%s %q %v}, want %v", pe.Code, pe.Message, reqID, want)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := canon(t, nodesToJSON(content)); !reflect.DeepEqual(got, c["content"]) {
					t.Errorf("content:\n got  %v\n want %v", got, c["content"])
				}
			}

			calls := []any{}
			for _, call := range f.calls {
				calls = append(calls, call)
			}
			if got := canon(t, calls); !reflect.DeepEqual(got, c["calls"]) {
				t.Errorf("calls:\n got  %v\n want %v", got, c["calls"])
			}

			var allowance, bed any
			if f.allowance != nil {
				allowance = *f.allowance
			}
			if f.bed != nil {
				bed = f.bed.String()
			}
			after := obj{"allowance": allowance, "bed_time": bed, "wake_time": f.wake.String(),
				"manual_lock": f.manual, "extension_seconds": f.extension}
			if got := canon(t, after); !reflect.DeepEqual(got, c["after"]) {
				t.Errorf("state after:\n got  %v\n want %v", got, c["after"])
			}
		})
	}
}
