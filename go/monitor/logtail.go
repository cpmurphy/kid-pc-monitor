package monitor

import (
	"bytes"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const tailBlockSize = 8192

// ReadLogTail returns up to tail lines from the end of the agent log and
// whether older lines exist. A missing (or non-regular) log has no lines.
//
// It reads backwards in blocks, as the Python implementation does, so a large
// log costs only what the tail needs. Blank lines at the end of the file are
// skipped; blank lines before the last line are kept. tail must be >= 0.
func (c *Control) ReadLogTail(tail int64) (lines []string, truncated bool, err error) {
	return readLogTail(c.agentLogPath, tail)
}

func readLogTail(path string, tail int64) ([]string, bool, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, false, err
	}
	if end == 0 {
		return nil, false, nil
	}

	remaining := end
	var fragment []byte
	var raw [][]byte // newest line first
	for remaining > 0 && int64(len(raw)) <= tail {
		size := min(int64(tailBlockSize), remaining)
		remaining -= size
		chunk := make([]byte, size)
		if _, err := f.ReadAt(chunk, remaining); err != nil && err != io.EOF {
			return nil, false, err
		}
		fragment = append(chunk, fragment...)
		parts := bytes.Split(fragment, []byte("\n"))
		if remaining > 0 {
			fragment = parts[0]
			parts = parts[1:]
		} else {
			fragment = nil
		}
		for i := len(parts) - 1; i >= 0; i-- {
			if len(parts[i]) > 0 || len(raw) > 0 {
				raw = append(raw, parts[i])
			}
			if int64(len(raw)) > tail {
				break
			}
		}
	}

	truncated := remaining > 0 || int64(len(raw)) > tail
	if int64(len(raw)) > tail {
		raw = raw[:tail]
	}
	lines := make([]string, len(raw))
	for i, line := range raw {
		lines[len(raw)-1-i] = decodeReplace(line)
	}
	return lines, truncated, nil
}

// decodeReplace decodes UTF-8 like Python's errors="replace": each maximal
// invalid prefix of a sequence becomes one U+FFFD (Go's own conversion would
// emit one per byte).
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			sb.WriteString(string(b[i : i+size]))
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += invalidPrefixLen(b[i:])
	}
	return sb.String()
}

// invalidPrefixLen is the length of the longest prefix of b that could begin a
// valid UTF-8 sequence (at least 1), for b that does not start with one.
func invalidPrefixLen(b []byte) int {
	lo, hi := byte(0x80), byte(0xBF) // allowed range of the 2nd byte
	need := 0
	switch lead := b[0]; {
	case lead >= 0xC2 && lead <= 0xDF:
		need = 1
	case lead == 0xE0:
		need, lo = 2, 0xA0
	case lead >= 0xE1 && lead <= 0xEC, lead == 0xEE, lead == 0xEF:
		need = 2
	case lead == 0xED:
		need, hi = 2, 0x9F
	case lead == 0xF0:
		need, lo = 3, 0x90
	case lead >= 0xF1 && lead <= 0xF3:
		need = 3
	case lead == 0xF4:
		need, hi = 3, 0x8F
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(b); n++ {
		if b[n] < lo || b[n] > hi {
			break
		}
		lo, hi = 0x80, 0xBF // later bytes are plain continuations
	}
	return n
}
