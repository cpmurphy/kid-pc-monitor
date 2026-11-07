// Package format holds the web panel's pure helpers: display formatting
// (panel_format.py), the agent-settings to panel PC-info conversion, panel
// action mapping and connection-error text (remote_client.py), and the
// dashboard status badge (scan_store.dashboard_status_key).
//
// testdata/panelformat/vectors.json is the checked-in contract from the
// original Python panel and vectors_test.go checks that this package agrees
// on every case.
//
// Values are dynamically typed as in Python; see package pyval.
package format

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"kidpcmonitor/panel/pyval"
)

// DefaultLogTailLines is agent_protocol.DEFAULT_LOG_TAIL_LINES.
const DefaultLogTailLines = 500

// FormatMinutesDuration formats a minute count as "H:MM", "N min", or
// "Not set" for nil. Fractions round half to even, and negative counts use
// floor division ("-1:55" for -5), exactly as Python does.
func FormatMinutesDuration(minutes any) string {
	if minutes == nil {
		return "Not set"
	}
	var total int64
	switch m := minutes.(type) {
	case int:
		total = int64(m)
	case int64:
		total = m
	default:
		f, ok := pyval.Number(minutes)
		if !ok {
			return "Not set"
		}
		total = pyval.RoundInt(f)
	}
	hours, mins := pyval.DivMod(total, 60)
	if hours != 0 {
		return fmt.Sprintf("%d:%02d", hours, mins)
	}
	return fmt.Sprintf("%d min", mins)
}

// FormatSecondsDuration is FormatMinutesDuration(seconds / 60).
func FormatSecondsDuration(seconds any) string {
	f, ok := pyval.Number(seconds)
	if !ok {
		return "Not set"
	}
	return FormatMinutesDuration(f / 60)
}

// FormatUsageDate formats an ISO calendar date as "Mon Oct 20"; anything
// else is returned unchanged.
func FormatUsageDate(day string) string {
	d, err := pyval.DateFromISOFormat(day)
	if err != nil {
		return day
	}
	return d.Format("Mon Jan") + " " + strconv.Itoa(d.Day())
}

// ParseRemainingMinutes reads a time_remaining value: a number, or text like
// "90 minutes" / "90 min" / "90". ok is false for anything else (None).
func ParseRemainingMinutes(value any) (minutes float64, ok bool) {
	switch v := value.(type) {
	case bool, nil:
		return 0, false
	case string:
		return parseRemainingText(v)
	}
	return pyval.Number(value)
}

// parseRemainingText matches
// ^\s*(-?\d+(?:\.\d+)?)\s*(?:min(?:ute)?s?)?\s*$ with Python's Unicode \s and
// \d, then converts the number as float() would.
func parseRemainingText(s string) (float64, bool) {
	rest := strings.TrimLeftFunc(s, pyval.IsSpace)
	rest = strings.TrimRightFunc(rest, pyval.IsSpace)
	var num strings.Builder
	i := 0
	runes := []rune(rest)
	if i < len(runes) && runes[i] == '-' {
		num.WriteByte('-')
		i++
	}
	digits := func() int {
		n := 0
		for i < len(runes) && unicode.IsDigit(runes[i]) {
			num.WriteString(strconv.Itoa(pyval.DigitValue(runes[i])))
			i++
			n++
		}
		return n
	}
	if digits() == 0 {
		return 0, false
	}
	if i+1 < len(runes) && runes[i] == '.' && unicode.IsDigit(runes[i+1]) {
		num.WriteByte('.')
		i++
		digits()
	}
	unit := strings.TrimLeftFunc(string(runes[i:]), pyval.IsSpace)
	switch unit {
	case "", "min", "mins", "minute", "minutes":
	default:
		return 0, false
	}
	f, err := strconv.ParseFloat(num.String(), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// RemainingMinutes is ParseRemainingMinutes as a template value: the minutes
// as float64, or nil.
func RemainingMinutes(value any) any {
	if m, ok := ParseRemainingMinutes(value); ok {
		return m
	}
	return nil
}

// FormatSnapshotRecordedAt formats a snapshot ISO timestamp for parents:
// "2:16pm", "2:16pm yesterday" or "2:16pm Jun 1".
//
// Times are shown at now's UTC offset (a fixed offset, as Python's
// datetime.now().astimezone() gives), and a timestamp without an offset is
// taken to be in it. Unparseable text is returned unchanged.
func FormatSnapshotRecordedAt(recordedAt string, now time.Time) string {
	if recordedAt == "" {
		return ""
	}
	dt, aware, err := pyval.FromISOFormat(recordedAt)
	if err != nil {
		return recordedAt
	}
	_, offset := now.Zone()
	display := time.FixedZone("", offset)
	if !aware {
		dt = time.Date(dt.Year(), dt.Month(), dt.Day(), dt.Hour(), dt.Minute(), dt.Second(),
			dt.Nanosecond(), display)
	}
	local := dt.In(display)
	ref := now.In(display)
	timeStr := compactClock(local)
	ly, lm, ld := local.Date()
	ry, rm, rd := ref.Date()
	if ly == ry && lm == rm && ld == rd {
		return timeStr
	}
	yy, ym, yd := time.Date(ry, rm, rd-1, 0, 0, 0, 0, time.UTC).Date()
	if ly == yy && lm == ym && ld == yd {
		return timeStr + " yesterday"
	}
	return fmt.Sprintf("%s %s %d", timeStr, local.Format("Jan"), ld)
}

func compactClock(t time.Time) string {
	hour := t.Hour() % 12
	if hour == 0 {
		hour = 12
	}
	suffix := "am"
	if t.Hour() >= 12 {
		suffix = "pm"
	}
	return fmt.Sprintf("%d:%02d%s", hour, t.Minute(), suffix)
}
