package state

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kidpcmonitor/policy"
)

// The golden vectors are generated from the Python implementation by
// tests/state_vectors_gen.py. Every case here must agree with it.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "state", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // inputs keep int/float distinctions, like Python's json
	var v obj
	if err := dec.Decode(&v); err != nil {
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

// plain turns json.Number into float64 so values compare with Go-produced JSON.
func plain(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = plain(x[i])
		}
		return out
	case map[string]any:
		out := make(obj, len(x))
		for k, e := range x {
			out[k] = plain(e)
		}
		return out
	}
	return v
}

// canon round-trips a Go value through JSON into the same shape as plain().
func canon(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func str(v any) string { s, _ := v.(string); return s }

func mustTOD(t *testing.T, s string) policy.TimeOfDay {
	t.Helper()
	tod, err := policy.ParseTimeHHMM(s)
	if err != nil {
		t.Fatal(err)
	}
	return tod
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := ParseISODatetime(s)
	if err != nil {
		t.Fatalf("ParseISODatetime(%q): %v", s, err)
	}
	return ts
}

func dailyJSON(d DailySettings) obj {
	var bed any
	if d.BedTime != nil {
		bed = d.BedTime.String()
	}
	var allowance any
	if d.Allowance != nil {
		allowance = *d.Allowance
	}
	return obj{"bed_time": bed, "wake_time": d.WakeTime.String(), "allowance": allowance}
}

func runtimeJSON(r RuntimeState) obj {
	return obj{
		"timestamp":                    FormatISO(r.Timestamp),
		"accumulated_seconds":          r.AccumulatedSeconds,
		"manual_lock_active":           r.ManualLockActive,
		"cumulative_extension_seconds": r.CumulativeExtensionSeconds,
	}
}

func makeDaily(t *testing.T, in obj) DailySettings {
	t.Helper()
	d := DailySettings{WakeTime: mustTOD(t, str(in["wake_time"]))}
	if s, ok := in["bed_time"].(string); ok {
		bed := mustTOD(t, s)
		d.BedTime = &bed
	}
	if n, ok := in["allowance"].(json.Number); ok {
		v, _ := n.Int64()
		d.Allowance = &v
	}
	return d
}

func makeRuntime(t *testing.T, in obj) RuntimeState {
	t.Helper()
	acc, _ := in["accumulated_seconds"].(json.Number).Float64()
	ext, _ := in["cumulative_extension_seconds"].(json.Number).Int64()
	return RuntimeState{
		Timestamp:                  mustTime(t, str(in["timestamp"])),
		AccumulatedSeconds:         acc,
		ManualLockActive:           in["manual_lock_active"].(bool),
		CumulativeExtensionSeconds: ext,
	}
}

// expectOutcome checks err against a vector's {"error": class} / {"ok": ...}
// and reports whether the case succeeded (so the caller can compare values).
func expectOutcome(t *testing.T, c obj, err error) bool {
	t.Helper()
	if want, isErr := c["error"]; isErr {
		if err == nil {
			t.Errorf("want %v, got success", want)
		} else if got := errorClass(err); got != want {
			t.Errorf("error class = %s (%v), want %v", got, err, want)
		}
		return false
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return false
	}
	return true
}

func TestVectorEffectiveAllowance(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "effective_allowance") {
		d := DailySettings{WakeTime: policy.DefaultWakeTime}
		if n, ok := c["allowance"].(json.Number); ok {
			v, _ := n.Int64()
			d.Allowance = &v
		}
		ext, _ := c["extension_seconds"].(json.Number).Int64()
		minutes, ok := EffectiveDailyAllowanceMinutes(d, RuntimeState{CumulativeExtensionSeconds: ext})
		want, wantOK := plain(c["result"]).(float64)
		if ok != wantOK || (ok && minutes != want) {
			t.Errorf("allowance=%v ext=%d: got %v, %v; want %v, %v", c["allowance"], ext, minutes, ok, want, wantOK)
		}
	}
}

func TestVectorRollover(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "rollover") {
		wake, now := mustTOD(t, str(c["wake"])), mustTime(t, str(c["now"]))
		r := RuntimeState{
			Timestamp: mustTime(t, str(c["timestamp"])), AccumulatedSeconds: 1234.5,
			ManualLockActive: true, CumulativeExtensionSeconds: 900,
		}
		if got := RuntimeStateIsCurrent(r, wake, now); got != c["current"] {
			t.Errorf("%v: current = %v, want %v", c, got, c["current"])
		}
		if got := ResetRuntimeIfNeeded(&r, wake, now); got != c["changed"] {
			t.Errorf("%v: changed = %v, want %v", c, got, c["changed"])
		}
		if got := canon(t, runtimeJSON(r)); !reflect.DeepEqual(got, plain(c["after"])) {
			t.Errorf("%v: after = %v, want %v", c, got, c["after"])
		}
	}
}

func TestVectorToDict(t *testing.T) {
	v := loadVectors(t)["to_dict"].(obj)
	for _, c := range v["daily"].([]any) {
		c := c.(obj)
		raw, err := DailyToJSON(makeDaily(t, c["in"].(obj)))
		if err != nil {
			t.Fatal(err)
		}
		var got any
		_ = json.Unmarshal(raw, &got)
		if !reflect.DeepEqual(got, plain(c["out"])) {
			t.Errorf("daily %v: got %s, want %v", c["in"], raw, c["out"])
		}
	}
	for _, c := range v["runtime"].([]any) {
		c := c.(obj)
		raw, err := RuntimeToJSON(makeRuntime(t, c["in"].(obj)))
		if err != nil {
			t.Fatal(err)
		}
		var got any
		_ = json.Unmarshal(raw, &got)
		if !reflect.DeepEqual(got, plain(c["out"])) {
			t.Errorf("runtime %v: got %s, want %v", c["in"], raw, c["out"])
		}
	}
}

func TestVectorLoadDaily(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "load_daily") {
		d, err := LoadDailyFromDocument(c["in"].(obj))
		if expectOutcome(t, c, err) {
			if got := canon(t, dailyJSON(d)); !reflect.DeepEqual(got, plain(c["ok"])) {
				t.Errorf("in %v: got %v, want %v", c["in"], got, c["ok"])
			}
		}
	}
}

func TestVectorIsCompleteDaily(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "is_complete_daily") {
		if got := IsCompleteDailyDocument(c["in"].(obj)); got != c["result"] {
			t.Errorf("in %v: got %v, want %v", c["in"], got, c["result"])
		}
	}
}

func TestVectorLoadRuntime(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "load_runtime") {
		r, err := LoadRuntimeFromDocument(c["in"].(obj))
		if expectOutcome(t, c, err) {
			if got := canon(t, runtimeJSON(r)); !reflect.DeepEqual(got, plain(c["ok"])) {
				t.Errorf("in %v: got %v, want %v", c["in"], got, c["ok"])
			}
		}
	}
}

func TestVectorLegacyToState(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "legacy_to_state") {
		d, r, err := LegacyToState(c["in"].(obj), mustTime(t, str(c["now"])))
		if expectOutcome(t, c, err) {
			got := obj{"daily": dailyJSON(d), "runtime": runtimeJSON(r)}
			if !reflect.DeepEqual(canon(t, got), plain(c["ok"])) {
				t.Errorf("in %v:\n got  %v\n want %v", c["in"], got, c["ok"])
			}
		}
	}
}

func writeFiles(t *testing.T, dir string, files obj) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(str(text)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readTree(t *testing.T, dir string) obj {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tree := obj{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			v = obj{"_raw": string(raw)}
		}
		tree[e.Name()] = v
	}
	return tree
}

func TestVectorStore(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "store") {
		t.Run(str(c["name"]), func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			writeFiles(t, dataDir, c["files"].(obj))
			programData := ""
			if pd, ok := c["program_data"].(obj); ok {
				programData = filepath.Join(root, "ProgramData", "KidPCMonitor")
				writeFiles(t, programData, pd)
			}
			now := mustTime(t, str(c["now"]))
			store := &Store{
				DataDir:        dataDir,
				CurrentUser:    str(c["user"]),
				Clock:          func() time.Time { return now },
				ProgramDataDir: programData,
				Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			}

			var err error
			var got obj
			if c["op"] == "save" {
				d := makeDaily(t, c["save_daily"].(obj))
				r := makeRuntime(t, c["save_runtime"].(obj))
				err = store.Save(d, &r)
				got = obj{}
			} else {
				var d DailySettings
				var r RuntimeState
				d, r, err = store.Load()
				got = obj{"daily": dailyJSON(d), "runtime": runtimeJSON(r)}
			}
			if expectOutcome(t, c, err) && c["op"] != "save" {
				if !reflect.DeepEqual(canon(t, got), plain(c["ok"])) {
					t.Errorf("result:\n got  %v\n want %v", got, c["ok"])
				}
			}
			if after := readTree(t, dataDir); !reflect.DeepEqual(after, plain(c["files_after"])) {
				t.Errorf("files after:\n got  %v\n want %v", after, plain(c["files_after"]))
			}
		})
	}
}

func TestVectorInstallerHelpers(t *testing.T) {
	for _, c := range cases(t, loadVectors(t), "installer_helpers") {
		t.Run(str(c["name"]), func(t *testing.T) {
			root := t.TempDir()
			profile, pd := filepath.Join(root, "profile"), filepath.Join(root, "pd")
			writeFiles(t, profile, c["profile"].(obj))
			writeFiles(t, pd, c["program_data"].(obj))

			found, source, err := FindCompleteDailySettings(
				filepath.Join(profile, DailySettingsFile), filepath.Join(pd, DailySettingsFile))
			if err != nil {
				t.Fatal(err)
			}
			if want, ok := c["found"].(obj); !ok {
				if found != nil {
					t.Errorf("found %v, want nothing", dailyJSON(*found))
				}
			} else if found == nil {
				t.Errorf("found nothing, want %v", want)
			} else {
				origin := "program_data"
				if filepath.Dir(source) == profile {
					origin = "profile"
				}
				if !reflect.DeepEqual(canon(t, dailyJSON(*found)), plain(want["daily"])) || origin != want["source"] {
					t.Errorf("found %v from %s, want %v", dailyJSON(*found), origin, want)
				}
			}

			target, err := ProgramDataTargetUser(pd)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := c["target_user"].(string)
			if target != want {
				t.Errorf("target user = %q, want %q", target, want)
			}
		})
	}
}

func TestISODatetimeRoundTrip(t *testing.T) {
	ts := time.Date(2026, 5, 17, 10, 0, 0, 250_000_000, time.UTC)
	if got := FormatISO(ts); got != "2026-05-17T10:00:00.250000" {
		t.Errorf("FormatISO = %s", got)
	}
	if got := FormatISOSeconds(ts); got != "2026-05-17T10:00:00" {
		t.Errorf("FormatISOSeconds = %s", got)
	}
	back, err := ParseISODatetime(FormatISO(ts))
	if err != nil || !back.Equal(ts) {
		t.Errorf("round trip = %v, %v", back, err)
	}
}

func TestWallClockIgnoresLocation(t *testing.T) {
	// 23:30 in UTC-8 is 07:30 the next day in UTC; the agent keeps the wall fields.
	now := time.Date(2026, 5, 17, 23, 30, 0, 0, time.FixedZone("PST", -8*3600))
	if w := policy.Wall(now); w.Hour() != 23 || w.Day() != 17 || w.Location() != time.UTC {
		t.Errorf("Wall(%v) = %v", now, w)
	}
}
