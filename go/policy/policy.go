// Package policy decides when the kid PC must be locked.
//
// It is a port of src/kid_pc_monitor/lock_policy.py: pure functions with no
// clock, filesystem or Windows dependency. testdata/policy/vectors.json is
// generated from the Python implementation and vectors_test.go checks that
// this package agrees on every case.
//
// # Wall-clock times
//
// The agent works in naive local wall-clock time, exactly as the Python code
// does: a time.Time argument contributes only its calendar date, hour, minute,
// second and sub-second fields, and its location is ignored. Pass time.Now()
// directly. Differences between two times are wall-clock differences, so a
// daylight-saving change does not shorten or lengthen a curfew.
package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimeOfDay is an HH:MM wall-clock time.
type TimeOfDay struct{ Hour, Minute int }

// DefaultWakeTime is the morning unlock when wake_time is not configured.
var DefaultWakeTime = TimeOfDay{7, 0}

// String formats as zero-padded HH:MM.
func (t TimeOfDay) String() string { return fmt.Sprintf("%02d:%02d", t.Hour, t.Minute) }

func (t TimeOfDay) minutes() int { return t.Hour*60 + t.Minute }

// Date is a calendar date.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// String formats as YYYY-MM-DD.
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day) }

// Before reports whether d is earlier than o.
func (d Date) Before(o Date) bool {
	if d.Year != o.Year {
		return d.Year < o.Year
	}
	if d.Month != o.Month {
		return d.Month < o.Month
	}
	return d.Day < o.Day
}

// Decision is the outcome of lock_decision.
type Decision struct {
	ShouldLock bool
	Reason     string
}

// ShouldMonitorUser reports whether restrictions apply to currentUser.
// A non-empty monitored list wins; otherwise a non-empty exempt list excludes.
func ShouldMonitorUser(currentUser string, monitored, exempt []string) bool {
	if len(monitored) > 0 {
		return contains(monitored, currentUser)
	}
	if len(exempt) > 0 {
		return !contains(exempt, currentUser)
	}
	return true
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// ParseTimeHHMM parses H:MM or HH:MM: one or two ASCII digits for the hour and
// exactly two for the minute, ignoring surrounding whitespace.
func ParseTimeHHMM(value string) (TimeOfDay, error) {
	text := strings.TrimFunc(value, isPySpace)
	hourText, minuteText, found := strings.Cut(text, ":")
	if !found || !asciiDigits(hourText, 1, 2) || !asciiDigits(minuteText, 2, 2) {
		return TimeOfDay{}, fmt.Errorf("invalid time %q; use HH:MM", value)
	}
	hour, _ := strconv.Atoi(hourText)
	minute, _ := strconv.Atoi(minuteText)
	if hour > 23 || minute > 59 {
		return TimeOfDay{}, fmt.Errorf("invalid time %q; hour/minute out of range", value)
	}
	return TimeOfDay{hour, minute}, nil
}

func asciiDigits(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isPySpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0:
		return true
	}
	return r > 0xff && (r == 0x1680 || (r >= 0x2000 && r <= 0x200a) ||
		r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000)
}

// Wall strips the location from t, keeping its wall-clock fields.
func Wall(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(),
		t.Nanosecond(), time.UTC)
}

func (t TimeOfDay) beforeOrAt(now time.Time) bool { return t.minutes() <= now.Hour()*60+now.Minute() }

// UsagePeriodDate labels the current daily usage period. The period starts at
// wakeTime each day (not midnight), so early-morning use before wake still
// counts toward the previous day's allowance.
func UsagePeriodDate(now time.Time, wakeTime TimeOfDay) Date {
	day := Wall(now)
	if now.Hour()*60+now.Minute() < wakeTime.minutes() {
		day = day.AddDate(0, 0, -1)
	}
	return Date{day.Year(), day.Month(), day.Day()}
}

// IsInBedtimeCurfew reports whether now falls in the overnight curfew from
// bedTime until wakeTime. Typical case: bedtime 21:00, wake 07:00 locks from
// 21:00 through 06:59.
func IsInBedtimeCurfew(now time.Time, bedTime, wakeTime TimeOfDay) bool {
	nowM, bedM, wakeM := now.Hour()*60+now.Minute(), bedTime.minutes(), wakeTime.minutes()
	switch {
	case bedM == wakeM:
		return false
	case bedM > wakeM:
		return nowM >= bedM || nowM < wakeM
	}
	return bedM <= nowM && nowM < wakeM
}

// Inputs are the facts a lock decision depends on. The zero value is a
// monitored user with no schedule, no allowance, and the default wake time.
type Inputs struct {
	Now time.Time
	// BedTime starts a curfew that lasts until wake time; nil means none.
	BedTime *TimeOfDay
	// AllowanceMinutes is the effective usage allowance (daily allowance plus
	// extensions); nil means no cap.
	AllowanceMinutes *float64
	// AccumulatedMinutes used so far in the current wake-to-wake period.
	AccumulatedMinutes float64
	// Exempt users have no restrictions (the inverse of Python's monitor_user,
	// so that the zero value is the safe, restricted case).
	Exempt           bool
	ManualLockActive bool
	// WakeTime defaults to DefaultWakeTime when nil.
	WakeTime *TimeOfDay
}

func (in Inputs) wake() TimeOfDay {
	if in.WakeTime == nil {
		return DefaultWakeTime
	}
	return *in.WakeTime
}

// Minutes is a convenience for building Inputs.AllowanceMinutes.
func Minutes(m float64) *float64 { return &m }

// At is a convenience for building Inputs.BedTime and Inputs.WakeTime.
func At(hour, minute int) *TimeOfDay { return &TimeOfDay{hour, minute} }

// formatAllowance renders an allowance as Python's f"{label}" would after
// int()/round(x, 1): "120" for whole numbers, otherwise one decimal place.
func formatAllowance(m float64) string {
	whole := int64(m)
	if m == float64(whole) {
		return strconv.FormatInt(whole, 10)
	}
	return strconv.FormatFloat(m, 'f', 1, 64)
}

// LockDecision decides whether the agent should enforce a lock at in.Now.
func LockDecision(in Inputs) Decision {
	if in.Exempt {
		return Decision{}
	}
	if in.ManualLockActive {
		return Decision{true, "Manual lock requested"}
	}
	wake := in.wake()
	if in.BedTime != nil && IsInBedtimeCurfew(in.Now, *in.BedTime, wake) {
		if in.Now.Hour()*60+in.Now.Minute() < wake.minutes() {
			return Decision{true, "Before wake-up time " + wake.String()}
		}
		return Decision{true, "Past bedtime " + in.BedTime.String()}
	}
	if in.AllowanceMinutes != nil && in.AccumulatedMinutes >= *in.AllowanceMinutes {
		return Decision{true, "Daily allowance of " + formatAllowance(*in.AllowanceMinutes) + " minutes reached"}
	}
	return Decision{}
}

// MinutesUntilLock returns the minutes until the next lock, 0 if already
// locked. ok is false when there is nothing to count down to (Python's None).
func MinutesUntilLock(in Inputs) (minutes float64, ok bool) {
	if in.Exempt {
		return 0, false
	}
	if LockDecision(in).ShouldLock {
		return 0, true
	}
	if in.BedTime != nil {
		now := Wall(in.Now)
		bed := time.Date(now.Year(), now.Month(), now.Day(), in.BedTime.Hour, in.BedTime.Minute, 0, 0, time.UTC)
		if !bed.After(now) {
			bed = bed.AddDate(0, 0, 1)
		}
		// timedelta.total_seconds() / 60, with microsecond resolution.
		minutes, ok = float64(bed.Sub(now).Microseconds())/1e6/60, true
	}
	if in.AllowanceMinutes != nil {
		remaining := *in.AllowanceMinutes - in.AccumulatedMinutes
		if !ok || remaining < minutes {
			minutes, ok = remaining, true
		}
	}
	return minutes, ok
}

// BriefEnforcementReason shortens a lock reason for protocol/UI display.
func BriefEnforcementReason(full string) string {
	lower := strings.ToLower(full)
	switch {
	case strings.Contains(lower, "before wake-up"):
		return "before wake-up"
	case strings.Contains(lower, "past bedtime"):
		return "past bedtime"
	case strings.Contains(lower, "daily allowance"):
		return "daily limit reached"
	}
	return full
}

// EnforcementState reports schedule/limit enforcement without considering a
// manual lock. reason is empty when active is false.
func EnforcementState(in Inputs) (active bool, reason string) {
	in.ManualLockActive = false
	d := LockDecision(in)
	if !d.ShouldLock {
		return false, ""
	}
	return true, BriefEnforcementReason(d.Reason)
}

// FormatAccessStatus composes a brief access status for the parent panel.
func FormatAccessStatus(manualLock, enforcementActive bool, enforcementReason string, screenLocked bool) string {
	switch {
	case manualLock && !enforcementActive:
		return "Locked — manual lock"
	case enforcementActive:
		if enforcementReason == "" {
			enforcementReason = "enforcement active"
		}
		return "Locked — " + enforcementReason
	case screenLocked:
		return "Screen locked"
	}
	return "Unlocked"
}
