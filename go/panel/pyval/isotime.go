package pyval

import (
	"errors"
	"fmt"
	"time"
)

// ErrISOFormat is returned for strings datetime.fromisoformat or
// date.fromisoformat reject.
var ErrISOFormat = errors.New("invalid isoformat string")

// FromISOFormat is datetime.fromisoformat (Python 3.11+): a date
// (YYYY-MM-DD, YYYYMMDD or an ISO week date), optionally followed by any
// single ASCII separator and a time (HH[:MM[:SS[.ffffff]]], or without
// colons) with an optional UTC offset (Z, ±HH[:MM[:SS[.ffffff]]]).
//
// aware reports whether the string had an offset. A naive result carries its
// wall-clock fields in time.UTC; callers attach the zone Python would assume.
//
// It follows CPython's _datetime parser. Known differences: hour 24 is
// rejected (newer Pythons accept 24:00 as the next midnight) and sub-second
// UTC offsets are truncated to whole seconds.
func FromISOFormat(s string) (t time.Time, aware bool, err error) {
	n := len(s)
	if n < 7 {
		return time.Time{}, false, ErrISOFormat
	}
	sep := isoDateLength(s)
	if sep < 0 || sep > n {
		return time.Time{}, false, ErrISOFormat
	}
	year, month, day, ok := parseISODate(s[:sep])
	if !ok {
		return time.Time{}, false, ErrISOFormat
	}
	var hour, minute, second, micro, offset int
	if n > sep {
		timeStr := s[sep+1:]
		if timeStr == "" {
			return time.Time{}, false, ErrISOFormat
		}
		var rv int
		rv, hour, minute, second, micro, offset = parseISOTime(timeStr)
		if rv < 0 {
			return time.Time{}, false, ErrISOFormat
		}
		aware = rv == 1
	}
	if hour > 23 || minute > 59 || second > 59 || offset <= -86400 || offset >= 86400 {
		return time.Time{}, false, ErrISOFormat
	}
	loc := time.UTC
	if aware {
		loc = time.FixedZone("", offset)
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, micro*1000, loc), aware, nil
}

// DateFromISOFormat is date.fromisoformat (Python 3.11+). The result is
// midnight UTC on that date.
func DateFromISOFormat(s string) (time.Time, error) {
	switch len(s) {
	case 7, 8, 10:
	default:
		return time.Time{}, ErrISOFormat
	}
	year, month, day, ok := parseISODate(s)
	if !ok {
		return time.Time{}, ErrISOFormat
	}
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// at reads s like a NUL-terminated C string.
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// isoDateLength is _find_isoformat_datetime_separator: where the date part
// of a datetime string ends.
func isoDateLength(s string) int {
	n := len(s)
	if n == 7 {
		return 7
	}
	if s[4] == '-' {
		if s[5] != 'W' {
			return 10
		}
		if n < 8 {
			return -1
		}
		if n > 8 && s[8] == '-' {
			if n == 9 {
				return -1
			}
			if n > 10 && isDigit(s[10]) {
				return 8
			}
			return 10
		}
		return 8
	}
	if s[4] == 'W' {
		idx := 7
		for idx < n && isDigit(s[idx]) {
			idx++
		}
		if idx < 9 {
			return idx
		}
		if idx%2 == 0 {
			return 7
		}
		return 8
	}
	return 8
}

func parseDigits(s string, i, count int) (int, int, bool) {
	v := 0
	for k := 0; k < count; k++ {
		c := at(s, i+k)
		if !isDigit(c) {
			return 0, i, false
		}
		v = v*10 + int(c-'0')
	}
	return v, i + count, true
}

// parseISODate is parse_isoformat_date plus the range checks date() makes;
// it requires the whole of s to be consumed.
func parseISODate(s string) (year, month, day int, ok bool) {
	year, p, ok := parseDigits(s, 0, 4)
	if !ok {
		return 0, 0, 0, false
	}
	useSep := at(s, p) == '-'
	if useSep {
		p++
	}
	if at(s, p) == 'W' {
		p++
		week, q, ok := parseDigits(s, p, 2)
		if !ok {
			return 0, 0, 0, false
		}
		p = q
		weekday := 1
		if p < len(s) {
			if useSep {
				if at(s, p) != '-' {
					return 0, 0, 0, false
				}
				p++
			}
			if weekday, p, ok = parseDigits(s, p, 1); !ok {
				return 0, 0, 0, false
			}
		}
		if p != len(s) {
			return 0, 0, 0, false
		}
		return isoWeekToDate(year, week, weekday)
	}
	if month, p, ok = parseDigits(s, p, 2); !ok {
		return 0, 0, 0, false
	}
	if useSep {
		if at(s, p) != '-' {
			return 0, 0, 0, false
		}
		p++
	}
	if day, p, ok = parseDigits(s, p, 2); !ok || p != len(s) {
		return 0, 0, 0, false
	}
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) {
		return 0, 0, 0, false
	}
	return year, month, day, true
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// isoWeekToDate is date.fromisocalendar.
func isoWeekToDate(year, week, weekday int) (int, int, int, bool) {
	if year < 1 || weekday < 1 || weekday > 7 || week < 1 {
		return 0, 0, 0, false
	}
	jan4 := time.Date(year, 1, 4, 0, 0, 0, 0, time.UTC)
	if week == 53 {
		// Only years starting on a Thursday, or leap years starting on a
		// Wednesday, have a week 53.
		first := jan4.AddDate(0, 0, -3).Weekday()
		leap := daysIn(year, 2) == 29
		if !(first == time.Thursday || (leap && first == time.Wednesday)) {
			return 0, 0, 0, false
		}
	} else if week > 53 {
		return 0, 0, 0, false
	}
	isoWeekday := (int(jan4.Weekday())+6)%7 + 1 // Monday=1
	monday := jan4.AddDate(0, 0, 1-isoWeekday)
	d := monday.AddDate(0, 0, (week-1)*7+weekday-1)
	return d.Year(), int(d.Month()), d.Day(), true
}

// parseISOTime is parse_isoformat_time: rv is 0 for a naive time, 1 for one
// with an offset and negative for an error.
func parseISOTime(s string) (rv, hour, minute, second, micro, offset int) {
	tz := 0
	for tz < len(s) && s[tz] != 'Z' && s[tz] != '+' && s[tz] != '-' {
		tz++
	}
	rv, hour, minute, second, micro = parseHHMMSSFF(s, 0, tz)
	if rv < 0 {
		return rv, 0, 0, 0, 0, 0
	}
	if tz == len(s) {
		if rv == 1 {
			return -5, 0, 0, 0, 0, 0
		}
		return 0, hour, minute, second, micro, 0
	}
	if s[tz] == 'Z' {
		if tz+1 != len(s) {
			return -5, 0, 0, 0, 0, 0
		}
		return 1, hour, minute, second, micro, 0
	}
	sign := 1
	if s[tz] == '-' {
		sign = -1
	}
	r, th, tm, ts, _ := parseHHMMSSFF(s, tz+1, len(s))
	if r != 0 {
		return -5, 0, 0, 0, 0, 0
	}
	return 1, hour, minute, second, micro, sign * (th*3600 + tm*60 + ts)
}

// parseHHMMSSFF is parse_hh_mm_ss_ff over s[start:end]. As in C, it may look
// at s[end] (the offset sign) and returns 1 when the string continues.
func parseHHMMSSFF(s string, start, end int) (rv, hour, minute, second, micro int) {
	vals := [3]int{}
	p := start
	hasSep := true
	for i := 0; i < 3; i++ {
		v, q, ok := parseDigits(s, p, 2)
		if !ok {
			return -3, 0, 0, 0, 0
		}
		vals[i] = v
		p = q
		c := at(s, p)
		p++
		if i == 0 {
			hasSep = c == ':'
		}
		if p >= end {
			if c != 0 {
				return 1, vals[0], vals[1], vals[2], 0
			}
			return 0, vals[0], vals[1], vals[2], 0
		}
		if hasSep && c == ':' {
			continue
		}
		if c == '.' || c == ',' {
			if i < 2 {
				return -3, 0, 0, 0, 0
			}
			break
		}
		if !hasSep {
			p--
		} else {
			return -4, 0, 0, 0, 0
		}
	}
	toParse := end - p
	if toParse > 6 {
		toParse = 6
	}
	if toParse <= 0 {
		return -3, 0, 0, 0, 0
	}
	us, q, ok := parseDigits(s, p, toParse)
	if !ok {
		return -3, 0, 0, 0, 0
	}
	for k := toParse; k < 6; k++ {
		us *= 10
	}
	p = q
	for isDigit(at(s, p)) {
		p++
	}
	if at(s, p) != 0 {
		return 1, vals[0], vals[1], vals[2], us
	}
	return 0, vals[0], vals[1], vals[2], us
}

// ISOFormat is datetime.isoformat(): microseconds only when non-zero, and
// the UTC offset (±HH:MM, with :SS when needed) only for an aware time.
func ISOFormat(t time.Time, aware bool) string {
	out := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		out += fmt.Sprintf(".%06d", us)
	}
	if aware {
		out += formatOffset(t)
	}
	return out
}

// ISOFormatSeconds is datetime.isoformat(timespec="seconds").
func ISOFormatSeconds(t time.Time, aware bool) string {
	out := t.Format("2006-01-02T15:04:05")
	if aware {
		out += formatOffset(t)
	}
	return out
}

func formatOffset(t time.Time) string {
	_, off := t.Zone()
	sign := '+'
	if off < 0 {
		sign, off = '-', -off
	}
	out := fmt.Sprintf("%c%02d:%02d", sign, off/3600, off/60%60)
	if s := off % 60; s != 0 {
		out += fmt.Sprintf(":%02d", s)
	}
	return out
}
