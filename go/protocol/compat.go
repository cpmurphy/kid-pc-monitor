package protocol

import (
	"fmt"
	"strconv"
	"strings"

	"kidpcmonitor/internal/pycompat"
)

// Value is a KDL scalar: nil, bool, int64 or string.
type Value = any

// Ptr returns a pointer to s, for the optional string fields in this package.
func Ptr(s string) *string { return &s }

// normalize widens the integer types callers are likely to pass.
func normalize(v Value) Value {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case uint32:
		return int64(n)
	}
	return v
}

type intStatus = pycompat.Status

const (
	intOK       = pycompat.OK
	intNotInt   = pycompat.NotInt
	intOverflow = pycompat.Overflow
)

func pyInt(s string) (int64, intStatus) { return pycompat.Int(s) }

// pyStr renders v the way Python's str() would.
func pyStr(v Value) string {
	switch x := normalize(v).(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case string:
		return x
	}
	return fmt.Sprint(v)
}

// pyRepr approximates Python's repr() for error messages.
func pyRepr(v Value) string {
	s, ok := normalize(v).(string)
	if !ok {
		return pyStr(v)
	}
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == rune(quote):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pyTruthy mirrors Python's bool().
func pyTruthy(v Value) bool {
	switch x := normalize(v).(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case string:
		return x != ""
	}
	return true
}
