// Package pycompat reproduces the few Python builtins whose exact behavior
// the on-disk and on-wire formats depend on.
package pycompat

import (
	"strings"
	"unicode"
)

// Status says how Int interpreted its input.
type Status int

const (
	OK Status = iota
	NotInt
	Overflow
)

func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Int mirrors the subset of Python's int(str) that matters here: surrounding
// whitespace, an optional sign, and ASCII digits with single underscores
// between digits. Values outside int64 report Overflow (Python would keep a
// big integer).
func Int(s string) (int64, Status) {
	s = strings.TrimFunc(s, isSpace)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, NotInt
	}
	var n uint64
	overflow := false
	prevUnderscore := true // forbids a leading underscore
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			if prevUnderscore {
				return 0, NotInt
			}
			prevUnderscore = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, NotInt
		}
		prevUnderscore = false
		d := uint64(c - '0')
		if n > (1<<63)/10 || n*10 > (1<<63)-d {
			overflow = true
			continue
		}
		n = n*10 + d
	}
	if prevUnderscore {
		return 0, NotInt
	}
	if overflow || (!neg && n > 1<<63-1) {
		return 0, Overflow
	}
	if neg {
		return -int64(n), OK
	}
	return int64(n), OK
}
