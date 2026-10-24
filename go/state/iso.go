package state

import (
	"fmt"
	"strings"
	"time"
)

type isoReader struct {
	s   string
	pos int
}

func (r *isoReader) done() bool { return r.pos >= len(r.s) }

func (r *isoReader) peek() byte {
	if r.done() {
		return 0
	}
	return r.s[r.pos]
}

func (r *isoReader) digits(n int) (int, bool) {
	if r.pos+n > len(r.s) {
		return 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		c := r.s[r.pos+i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	r.pos += n
	return v, true
}

func (r *isoReader) eat(c byte) bool {
	if r.peek() == c && !r.done() {
		r.pos++
		return true
	}
	return false
}

func isoError(s string) error { return valueErrorf("Invalid isoformat string: %q", s) }

func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func readDate(r *isoReader, s string) (year, month, day int, err error) {
	var ok bool
	if year, ok = r.digits(4); !ok || !r.eat('-') {
		return 0, 0, 0, isoError(s)
	}
	if month, ok = r.digits(2); !ok || !r.eat('-') {
		return 0, 0, 0, isoError(s)
	}
	if day, ok = r.digits(2); !ok {
		return 0, 0, 0, isoError(s)
	}
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, time.Month(month)) {
		return 0, 0, 0, valueErrorf("day is out of range for month in %q", s)
	}
	return year, month, day, nil
}

// ParseISODate parses YYYY-MM-DD like date.fromisoformat.
func ParseISODate(s string) (year int, month time.Month, day int, err error) {
	r := &isoReader{s: s}
	y, m, d, err := readDate(r, s)
	if err != nil {
		return 0, 0, 0, err
	}
	if !r.done() {
		return 0, 0, 0, isoError(s)
	}
	return y, time.Month(m), d, nil
}

// ParseISODatetime parses an ISO 8601 date-time like datetime.fromisoformat
// and returns its wall-clock fields in UTC; any UTC offset is discarded.
// Accepted: YYYY-MM-DD, optionally followed by 'T' or ' ' and HH[:MM[:SS[.f]]],
// optionally followed by Z or an offset such as +02:00 or -0530.
func ParseISODatetime(s string) (time.Time, error) {
	r := &isoReader{s: s}
	year, month, day, err := readDate(r, s)
	if err != nil {
		return time.Time{}, err
	}
	hour, minute, second, nanos := 0, 0, 0, 0
	if !r.done() {
		if sep := r.peek(); sep != 'T' && sep != ' ' {
			return time.Time{}, isoError(s)
		}
		r.pos++
		var ok bool
		if hour, ok = r.digits(2); !ok {
			return time.Time{}, isoError(s)
		}
		if r.eat(':') {
			if minute, ok = r.digits(2); !ok {
				return time.Time{}, isoError(s)
			}
			if r.eat(':') {
				if second, ok = r.digits(2); !ok {
					return time.Time{}, isoError(s)
				}
				if c := r.peek(); (c == '.' || c == ',') && !r.done() {
					r.pos++
					start := r.pos
					for !r.done() && r.peek() >= '0' && r.peek() <= '9' {
						r.pos++
					}
					frac := r.s[start:r.pos]
					if frac == "" {
						return time.Time{}, isoError(s)
					}
					if len(frac) > 6 {
						frac = frac[:6] // datetime keeps microseconds
					}
					frac += strings.Repeat("0", 6-len(frac))
					micros := 0
					for _, c := range frac {
						micros = micros*10 + int(c-'0')
					}
					nanos = micros * 1000
				}
			}
		}
		if hour > 23 || minute > 59 || second > 59 {
			return time.Time{}, valueErrorf("time field out of range in %q", s)
		}
		if err := skipOffset(r, s); err != nil {
			return time.Time{}, err
		}
		if !r.done() {
			return time.Time{}, isoError(s)
		}
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, nanos, time.UTC), nil
}

// skipOffset consumes an optional Z / ±HH[:MM[:SS]] / ±HHMM suffix.
func skipOffset(r *isoReader, s string) error {
	if r.done() {
		return nil
	}
	if r.eat('Z') {
		return nil
	}
	if c := r.peek(); c != '+' && c != '-' {
		return isoError(s)
	}
	r.pos++
	hh, ok := r.digits(2)
	if !ok {
		return isoError(s)
	}
	mm, ss := 0, 0
	if r.eat(':') {
		if mm, ok = r.digits(2); !ok {
			return isoError(s)
		}
		if r.eat(':') {
			if ss, ok = r.digits(2); !ok {
				return isoError(s)
			}
		}
	} else if !r.done() {
		if mm, ok = r.digits(2); !ok {
			return isoError(s)
		}
	}
	if hh > 23 || mm > 59 || ss > 59 {
		return valueErrorf("offset out of range in %q", s)
	}
	return nil
}

// FormatISO renders t like datetime.isoformat: whole seconds, plus six
// fractional digits only when the microsecond part is non-zero.
func FormatISO(t time.Time) string {
	out := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		out += fmt.Sprintf(".%06d", us)
	}
	return out
}

// FormatISOSeconds renders t like isoformat(timespec="seconds").
func FormatISOSeconds(t time.Time) string { return t.Format("2006-01-02T15:04:05") }
