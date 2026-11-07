package format

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kidpcmonitor/panel/pyval"
)

// The golden vectors are the checked-in contract, originally generated from
// the Python implementation. Every case here must agree with them,
// including the int/float kind of every number.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "panelformat", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyval.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(obj)
}

func cases(t *testing.T, v obj, section string) []obj {
	t.Helper()
	list, ok := v[section].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("section %q missing or empty", section)
	}
	out := make([]obj, len(list))
	for i, c := range list {
		out[i] = c.(obj)
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

func mustISO(t *testing.T, s string) time.Time {
	t.Helper()
	tm, aware, err := pyval.FromISOFormat(s)
	if err != nil || !aware {
		t.Fatalf("bad now %q: %v", s, err)
	}
	return tm
}

func TestFormatMinutesDuration(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_minutes_duration") {
		if got := FormatMinutesDuration(c["in"]); got != c["out"] {
			t.Errorf("FormatMinutesDuration(%v) = %q, want %q", c["in"], got, c["out"])
		}
	}
}

func TestFormatSecondsDuration(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_seconds_duration") {
		if got := FormatSecondsDuration(c["in"]); got != c["out"] {
			t.Errorf("FormatSecondsDuration(%v) = %q, want %q", c["in"], got, c["out"])
		}
	}
}

func TestFormatUsageDate(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_usage_date") {
		if got := FormatUsageDate(str(c["in"])); got != c["out"] {
			t.Errorf("FormatUsageDate(%q) = %q, want %q", c["in"], got, c["out"])
		}
	}
}

func TestParseRemainingMinutes(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "parse_remaining_minutes") {
		got := RemainingMinutes(c["in"])
		if !reflect.DeepEqual(got, c["out"]) {
			t.Errorf("ParseRemainingMinutes(%#v) = %#v, want %#v", c["in"], got, c["out"])
		}
	}
}

func TestFormatSnapshotRecordedAt(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_snapshot_recorded_at") {
		now := mustISO(t, str(c["now"]))
		got := FormatSnapshotRecordedAt(str(c["recorded_at"]), now)
		if got != c["out"] {
			t.Errorf("FormatSnapshotRecordedAt(%q, now=%s) = %q, want %q",
				c["recorded_at"], c["now"], got, c["out"])
		}
	}
}

func TestSettingsToPCInfo(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "settings_to_pc_info") {
		settings := c["settings"].(obj)
		got, err := SettingsToPCInfo(settings, str(c["host"]), str(c["hostname_fallback"]))
		if want, ok := c["error"]; ok {
			pe, isPy := err.(*pyval.Error)
			if !isPy || pe.Type != want {
				t.Errorf("SettingsToPCInfo(%v): err %v, want %v", settings, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("SettingsToPCInfo(%v): %v", settings, err)
			continue
		}
		if want := c["result"]; !reflect.DeepEqual(got, want) {
			t.Errorf("SettingsToPCInfo(%v)\n got  %#v\n want %#v", settings, got, want)
		}
	}
}

func TestActionRequestFields(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "action_request_fields") {
		name := str(c["action_name"])
		payload, _ := c["payload"].(obj)
		got, err := ActionRequestFields(name, payload)
		if want, ok := c["error"]; ok {
			if err == nil {
				t.Errorf("ActionRequestFields(%q, %v) = %+v, want error %q", name, payload, got, want)
			} else if msg := InvalidActionMessage(name, err); msg != want {
				t.Errorf("ActionRequestFields(%q, %v) error %q, want %q", name, payload, msg, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("ActionRequestFields(%q, %v): %v", name, payload, err)
			continue
		}
		var gotVar, gotTail any
		if got.Var != nil {
			gotVar = *got.Var
		}
		if got.Tail != nil {
			gotTail = *got.Tail
		}
		gotObj := obj{"action": got.Action, "var": gotVar, "val": got.Val, "tail": gotTail}
		if want := c["result"]; !reflect.DeepEqual(gotObj, want) {
			t.Errorf("ActionRequestFields(%q, %v) = %#v, want %#v", name, payload, gotObj, want)
		}
	}
}

func TestFormatAgentConnectionError(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_agent_connection_error") {
		if got := FormatAgentConnectionError(str(c["in"])); got != c["out"] {
			t.Errorf("FormatAgentConnectionError(%q) = %q, want %q", c["in"], got, c["out"])
		}
	}
}

func TestDashboardStatusKey(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "dashboard_status_key") {
		if got := DashboardStatusKey(c["in"].(obj)); got != c["out"] {
			t.Errorf("DashboardStatusKey(%v) = %q, want %q", c["in"], got, c["out"])
		}
	}
}

// pyval is pinned here too, since its vectors live with the formatter's.

func TestPyvalFromISOFormat(t *testing.T) {
	sub := loadVectors(t)["pyval"].(obj)
	for _, c := range cases(t, sub, "datetime_fromisoformat") {
		in := str(c["in"])
		tm, aware, err := pyval.FromISOFormat(in)
		var got any
		if err == nil {
			got = pyval.ISOFormat(tm, aware)
		}
		if got != c["out"] {
			t.Errorf("FromISOFormat(%q) = %v, want %v", in, got, c["out"])
		}
	}
	for _, c := range cases(t, sub, "date_fromisoformat") {
		in := str(c["in"])
		d, err := pyval.DateFromISOFormat(in)
		var got any
		if err == nil {
			got = d.Format("2006-01-02")
		}
		if got != c["out"] {
			t.Errorf("DateFromISOFormat(%q) = %v, want %v", in, got, c["out"])
		}
	}
}

func TestPyvalInt(t *testing.T) {
	sub := loadVectors(t)["pyval"].(obj)
	for _, c := range cases(t, sub, "int") {
		n, err := pyval.Int(c["in"])
		if want, ok := c["error"]; ok {
			pe, isPy := err.(*pyval.Error)
			if !isPy || pe.Type != want || pe.Msg != c["message"] {
				t.Errorf("Int(%#v) err %v, want %v %q", c["in"], err, want, c["message"])
			}
			continue
		}
		if err != nil || n != c["result"] {
			t.Errorf("Int(%#v) = %d, %v; want %v", c["in"], n, err, c["result"])
		}
	}
}

func TestPyvalRepr(t *testing.T) {
	sub := loadVectors(t)["pyval"].(obj)
	for _, c := range cases(t, sub, "float_repr") {
		f, _ := pyval.Number(c["in"])
		if got := pyval.FloatRepr(f); got != c["out"] {
			t.Errorf("FloatRepr(%v) = %q, want %q", c["in"], got, c["out"])
		}
	}
	for _, c := range cases(t, sub, "json_dumps") {
		got, err := pyval.EncodeJSON(c["in"])
		if err != nil || got != c["out"] {
			t.Errorf("EncodeJSON(%#v) = %q, %v; want %q", c["in"], got, err, c["out"])
		}
	}
	for _, c := range cases(t, sub, "str_repr") {
		if got := pyval.Repr(str(c["in"])); got != c["out"] {
			t.Errorf("Repr(%q) = %q, want %q", c["in"], got, c["out"])
		}
	}
}
