package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The golden vectors are generated from the Python implementation by
// tests/policy_vectors_gen.py. Every case here must agree with it.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "policy", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v obj
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
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

func mustTime(t *testing.T, s string) TimeOfDay {
	t.Helper()
	tod, err := ParseTimeHHMM(s)
	if err != nil {
		t.Fatalf("ParseTimeHHMM(%q): %v", s, err)
	}
	return tod
}

func optTime(t *testing.T, v any) *TimeOfDay {
	if v == nil {
		return nil
	}
	tod := mustTime(t, v.(string))
	return &tod
}

func parseNow(t *testing.T, s string) time.Time {
	t.Helper()
	now, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func strList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, e := range list {
		out = append(out, e.(string))
	}
	return out
}

func TestVectorDefaultWakeTime(t *testing.T) {
	if got := DefaultWakeTime.String(); got != loadVectors(t)["default_wake_time"] {
		t.Errorf("DefaultWakeTime = %s", got)
	}
}

func TestVectorShouldMonitorUser(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "should_monitor_user") {
		got := ShouldMonitorUser(str(c["user"]), strList(c["monitored"]), strList(c["exempt"]))
		if got != c["result"] {
			t.Errorf("ShouldMonitorUser(%v, %v, %v) = %v, want %v",
				c["user"], c["monitored"], c["exempt"], got, c["result"])
		}
	}
}

func TestVectorParseTimeHHMM(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "parse_time_hhmm") {
		got, err := ParseTimeHHMM(str(c["input"]))
		if _, isErr := c["error"]; isErr {
			if err == nil {
				t.Errorf("ParseTimeHHMM(%q) = %v, want error", c["input"], got)
			}
			continue
		}
		if err != nil || got.String() != c["result"] {
			t.Errorf("ParseTimeHHMM(%q) = %v, %v; want %v", c["input"], got, err, c["result"])
		}
	}
}

func TestVectorUsagePeriodDate(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "usage_period_date") {
		got := UsagePeriodDate(parseNow(t, str(c["now"])), mustTime(t, str(c["wake"]))).String()
		if got != c["result"] {
			t.Errorf("UsagePeriodDate(%v, %v) = %s, want %v", c["now"], c["wake"], got, c["result"])
		}
	}
}

func TestVectorIsInBedtimeCurfew(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "is_in_bedtime_curfew") {
		got := IsInBedtimeCurfew(parseNow(t, str(c["now"])), mustTime(t, str(c["bed"])), mustTime(t, str(c["wake"])))
		if got != c["result"] {
			t.Errorf("IsInBedtimeCurfew(%v, bed %v, wake %v) = %v, want %v",
				c["now"], c["bed"], c["wake"], got, c["result"])
		}
	}
}

func TestVectorDecisions(t *testing.T) {
	for i, c := range cases(t, loadVectors(t), "decisions") {
		in := c["in"].(obj)
		inputs := Inputs{
			Now:                parseNow(t, str(in["now"])),
			BedTime:            optTime(t, in["bed"]),
			AccumulatedMinutes: in["accumulated"].(float64),
			Exempt:             !in["monitor"].(bool),
			ManualLockActive:   in["manual"].(bool),
			WakeTime:           optTime(t, in["wake"]),
		}
		if a, ok := in["allowance"].(float64); ok {
			inputs.AllowanceMinutes = Minutes(a)
		}
		label := func() string { b, _ := json.Marshal(in); return string(b) }

		d := LockDecision(inputs)
		if d.ShouldLock != c["should_lock"] || d.Reason != c["reason"] {
			t.Errorf("#%d LockDecision(%s) = %+v, want lock=%v reason=%q", i, label(), d, c["should_lock"], c["reason"])
		}

		minutes, ok := MinutesUntilLock(inputs)
		want, wantOK := c["minutes"].(float64)
		if ok != wantOK || (ok && minutes != want) {
			t.Errorf("#%d MinutesUntilLock(%s) = %v, %v; want %v, %v", i, label(), minutes, ok, want, wantOK)
		}

		active, reason := EnforcementState(inputs)
		wantReason, _ := c["enforcement_reason"].(string)
		if active != c["enforcement_active"] || reason != wantReason {
			t.Errorf("#%d EnforcementState(%s) = %v, %q; want %v, %q", i, label(), active, reason,
				c["enforcement_active"], wantReason)
		}
	}
}

func TestVectorBriefEnforcementReason(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "brief_enforcement_reason") {
		if got := BriefEnforcementReason(str(c["reason"])); got != c["result"] {
			t.Errorf("BriefEnforcementReason(%q) = %q, want %v", c["reason"], got, c["result"])
		}
	}
}

func TestVectorFormatAccessStatus(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "format_access_status") {
		got := FormatAccessStatus(c["manual_lock"].(bool), c["enforcement_active"].(bool),
			str(c["enforcement_reason"]), c["screen_locked"].(bool))
		if got != c["result"] {
			t.Errorf("FormatAccessStatus(%v) = %q, want %v", c, got, c["result"])
		}
	}
}

func TestZeroValueInputsAreRestricted(t *testing.T) {
	in := Inputs{Now: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC), ManualLockActive: true}
	if d := LockDecision(in); !d.ShouldLock {
		t.Errorf("zero-value Inputs must not be exempt: %+v", d)
	}
}
