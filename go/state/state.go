package state

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"kidpcmonitor/policy"
)

// DailySettings are the parent-configured schedule and cap.
type DailySettings struct {
	BedTime   *policy.TimeOfDay // nil: no curfew
	WakeTime  policy.TimeOfDay
	Allowance *int64 // minutes; nil: no screen-time cap
}

// RuntimeState is what the agent has observed today.
type RuntimeState struct {
	Timestamp                  time.Time // naive wall clock of the last save
	AccumulatedSeconds         float64
	ManualLockActive           bool
	CumulativeExtensionSeconds int64
}

// EffectiveDailyAllowanceMinutes returns the enforced cap in minutes. ok is
// false when there is no usage cap.
func EffectiveDailyAllowanceMinutes(d DailySettings, r RuntimeState) (minutes float64, ok bool) {
	extension := float64(r.CumulativeExtensionSeconds) / 60
	if d.Allowance == nil {
		if extension <= 0 {
			return 0, false
		}
		return extension, true
	}
	return float64(*d.Allowance) + extension, true
}

// RuntimeStateIsCurrent reports whether r belongs to the usage period that
// contains now.
func RuntimeStateIsCurrent(r RuntimeState, wake policy.TimeOfDay, now time.Time) bool {
	return policy.UsagePeriodDate(r.Timestamp, wake) == policy.UsagePeriodDate(now, wake)
}

// FreshRuntimeState is an empty runtime state stamped now.
func FreshRuntimeState(now time.Time) RuntimeState { return RuntimeState{Timestamp: now} }

// ResetRuntimeForNewPeriod zeroes the daily counters and clears the manual lock.
func ResetRuntimeForNewPeriod(r *RuntimeState, now time.Time) { *r = FreshRuntimeState(now) }

// ResetRuntimeIfNeeded resets r when it is from an earlier usage period and
// reports whether it did.
func ResetRuntimeIfNeeded(r *RuntimeState, wake policy.TimeOfDay, now time.Time) bool {
	if RuntimeStateIsCurrent(*r, wake, now) {
		return false
	}
	ResetRuntimeForNewPeriod(r, now)
	return true
}

// round3 mirrors Python's round(x, 3).
func round3(x float64) float64 {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return x
	}
	rounded, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 3, 64), 64)
	return rounded
}

// dailyFile and runtimeFile fix the key order Python writes.
type dailyFile struct {
	WakeTime  string  `json:"wake_time"`
	Allowance *int64  `json:"allowance"`
	BedTime   *string `json:"bed_time"`
}

type runtimeFile struct {
	Timestamp                  string  `json:"timestamp"`
	AccumulatedSeconds         float64 `json:"accumulated_seconds"`
	ManualLockActive           bool    `json:"manual_lock_active"`
	CumulativeExtensionSeconds int64   `json:"cumulative_extension_seconds"`
}

func dailyToFile(d DailySettings) dailyFile {
	f := dailyFile{WakeTime: d.WakeTime.String(), Allowance: d.Allowance}
	if d.BedTime != nil {
		s := d.BedTime.String()
		f.BedTime = &s
	}
	return f
}

func runtimeToFile(r RuntimeState) runtimeFile {
	return runtimeFile{
		Timestamp:                  FormatISOSeconds(r.Timestamp),
		AccumulatedSeconds:         round3(r.AccumulatedSeconds),
		ManualLockActive:           r.ManualLockActive,
		CumulativeExtensionSeconds: r.CumulativeExtensionSeconds,
	}
}

// DailyToJSON serializes d as daily_settings.json holds it.
func DailyToJSON(d DailySettings) ([]byte, error) {
	return json.MarshalIndent(dailyToFile(d), "", "  ")
}

// RuntimeToJSON serializes r as state.json holds it.
func RuntimeToJSON(r RuntimeState) ([]byte, error) {
	return json.MarshalIndent(runtimeToFile(r), "", "  ")
}

// stringTime parses a JSON value that must be an HH:MM string. Any other type
// is a ValueError, as Python's str() of it is never a valid time.
func stringTime(v any) (policy.TimeOfDay, error) {
	s, ok := v.(string)
	if !ok {
		return policy.TimeOfDay{}, valueErrorf("invalid time %v; use HH:MM", v)
	}
	t, err := policy.ParseTimeHHMM(s)
	if err != nil {
		return t, &ValueError{err.Error()}
	}
	return t, nil
}

// LoadDailyFromDocument builds DailySettings from a decoded daily_settings.json.
func LoadDailyFromDocument(data Document) (DailySettings, error) {
	var d DailySettings
	d.WakeTime = policy.DefaultWakeTime
	if v, present := data["wake_time"]; present {
		wake, err := stringTime(v)
		if err != nil {
			return d, err
		}
		d.WakeTime = wake
	}
	if v := data["bed_time"]; v != nil && v != "" {
		bed, err := stringTime(v)
		if err != nil {
			return d, err
		}
		d.BedTime = &bed
	}
	if v := data["allowance"]; v != nil {
		n, err := toInt(v)
		if err != nil {
			return d, err
		}
		d.Allowance = &n
	}
	return d, nil
}

// IsCompleteDailyDocument reports whether wake_time, bed_time and a positive
// allowance are all configured and valid.
func IsCompleteDailyDocument(data Document) bool {
	if !truthy(data["wake_time"]) || !truthy(data["bed_time"]) || data["allowance"] == nil {
		return false
	}
	allowance, err := toInt(data["allowance"])
	if err != nil || allowance <= 0 {
		return false
	}
	d, err := LoadDailyFromDocument(data)
	return err == nil && d.BedTime != nil && d.Allowance != nil && *d.Allowance > 0
}

// LoadRuntimeFromDocument builds RuntimeState from a decoded state.json.
func LoadRuntimeFromDocument(data Document) (RuntimeState, error) {
	var r RuntimeState
	raw, ok := data["timestamp"].(string)
	if !ok {
		return r, valueErrorf("state.json missing timestamp")
	}
	ts, err := ParseISODatetime(raw)
	if err != nil {
		return r, err
	}
	r.Timestamp = ts
	if v, present := data["accumulated_seconds"]; present {
		if r.AccumulatedSeconds, err = toFloat(v); err != nil {
			return r, err
		}
	}
	r.ManualLockActive = truthy(data["manual_lock_active"])
	if v, present := data["cumulative_extension_seconds"]; present {
		if r.CumulativeExtensionSeconds, err = toInt(v); err != nil {
			return r, err
		}
	}
	return r, nil
}

// legacyBedTime mirrors _legacy_lock_times_to_bed_time: the first legacy lock
// time becomes the bed time.
func legacyBedTime(raw any) (*policy.TimeOfDay, error) {
	if !truthy(raw) {
		return nil, nil
	}
	var first any
	switch x := raw.(type) {
	case []any:
		first = x[0]
	case string:
		first = string([]rune(x)[0])
	case map[string]any:
		return nil, &ValueError{"KeyError: 0"} // Python: KeyError; never written by any version
	default:
		return nil, typeErrorf("%s is not subscriptable", typeName(raw))
	}
	s, isString := first.(string)
	if !isString || !strings.Contains(s, ":") {
		return nil, nil
	}
	t, err := policy.ParseTimeHHMM(s)
	if err != nil {
		return nil, &ValueError{err.Error()}
	}
	return &t, nil
}

// LegacyToState converts a legacy pc_control_state.json payload into current
// settings and runtime state as of now.
func LegacyToState(legacy Document, now time.Time) (DailySettings, RuntimeState, error) {
	var d DailySettings
	var r RuntimeState
	d.WakeTime = policy.DefaultWakeTime
	if s, ok := legacy["wake_time"].(string); ok {
		wake, err := policy.ParseTimeHHMM(s)
		if err != nil {
			return d, r, &ValueError{err.Error()}
		}
		d.WakeTime = wake
	}
	bed, err := legacyBedTime(legacy["lock_times"])
	if err != nil {
		return d, r, err
	}
	d.BedTime = bed
	if v := legacy["usage_allowance"]; v != nil {
		n, err := toInt(v)
		if err != nil {
			return d, r, err
		}
		d.Allowance = &n
	}

	r = FreshRuntimeState(now)
	if v, present := legacy["accumulated_seconds"]; present {
		if r.AccumulatedSeconds, err = toFloat(v); err != nil {
			return d, r, err
		}
	}
	r.ManualLockActive = truthy(legacy["manual_lock_active"])

	// Python first checks whether the runtime (stamped now) is stale, which it
	// never is, and only then looks at the legacy accumulation date.
	if v, present := legacy["accumulated_date"]; present {
		s, ok := v.(string)
		if !ok {
			return d, r, typeErrorf("fromisoformat: argument must be str")
		}
		y, m, day, err := ParseISODate(s)
		if err != nil {
			return d, r, err
		}
		saved := policy.Date{Year: y, Month: m, Day: day}
		if saved.Before(policy.UsagePeriodDate(now, d.WakeTime)) {
			ResetRuntimeForNewPeriod(&r, now)
		}
	}
	return d, r, nil
}
