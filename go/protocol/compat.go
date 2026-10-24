package protocol

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
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

// pySpace matches the characters Python's str.strip() removes.
func pySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// maxParsedInt bounds numbers accepted from request fields.
const maxParsedInt = 1 << 53

// ParseInt reads a whole-number request field: an int, or a decimal string
// such as "15" or " -3 " (ASCII digits, optional sign), within ±2^53. Anything
// else is an invalid_value error carrying reqID.
func ParseInt(raw Value, reqID *string) (int64, error) {
	var n int64
	switch x := normalize(raw).(type) {
	case int64:
		n = x
	case string:
		text := strings.TrimFunc(x, pySpace)
		digits := strings.TrimLeft(text, "+-")
		if len(text)-len(digits) > 1 || !asciiDigits(digits) {
			return 0, perr(InvalidValue, "expected a number", reqID)
		}
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, perr(InvalidValue, "number out of range", reqID)
		}
		n = parsed
	default:
		return 0, perr(InvalidValue, "expected a number", reqID)
	}
	if n > maxParsedInt || n < -maxParsedInt {
		return 0, perr(InvalidValue, "number out of range", reqID)
	}
	return n, nil
}

func asciiDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
