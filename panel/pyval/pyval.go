// Package pyval reproduces the value semantics of the original Python panel,
// so this panel reads databases and JSON that panel wrote (60 and 60.0 are
// different, and truthiness, int(), repr and fromisoformat follow that code).
//
// # Values
//
// Panel data is dynamically typed JSON, as in Python. A value is one of
// nil (None), bool, int64 (int), float64 (float), string (str), []any (list)
// or map[string]any (dict). The int/float distinction matters: Python writes
// 60 and 60.0 differently, and both end up in panel.db. Plain Go int is also
// accepted wherever an int64 is.
//
// The helpers are tested directly and through the golden vectors of the
// packages that use them (testdata/panelformat).
package pyval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// Error is a Python exception: Type is the exception class name ("TypeError",
// "ValueError", "KeyError", "OverflowError") and Msg is str(exc).
type Error struct {
	Type string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func typeError(msg string) *Error  { return &Error{Type: "TypeError", Msg: msg} }
func valueError(msg string) *Error { return &Error{Type: "ValueError", Msg: msg} }

// KeyError is the exception dict[key] raises for a missing key; its str() is
// the repr of the key.
func KeyError(key string) *Error { return &Error{Type: "KeyError", Msg: Repr(key)} }

// TypeName is type(v).__name__.
func TypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int, int64:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any:
		return "list"
	case map[string]any:
		return "dict"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// Truthy is bool(v).
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) != 0
	case map[string]any:
		return len(x) != 0
	default:
		return true
	}
}

// Or is Python's "a or b": a when it is truthy, otherwise b.
func Or(a, b any) any {
	if Truthy(a) {
		return a
	}
	return b
}

// Number returns v as a float64 when it is a Python number (bool, int or
// float), as arithmetic would use it.
func Number(v any) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// Int is int(v) for the value kinds the panel sees.
//
// Known difference: Python ints are unbounded; results outside int64 are an
// OverflowError here.
func Int(v any) (int64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case float64:
		switch {
		case math.IsNaN(x):
			return 0, valueError("cannot convert float NaN to integer")
		case math.IsInf(x, 0):
			return 0, &Error{Type: "OverflowError", Msg: "cannot convert float infinity to integer"}
		}
		t := math.Trunc(x)
		if t < -(1<<63) || t >= 1<<63 {
			return 0, &Error{Type: "OverflowError", Msg: "integer out of int64 range"}
		}
		return int64(t), nil
	case string:
		return parseIntLiteral(x)
	}
	return 0, typeError("int() argument must be a string, a bytes-like object or a real number, not " +
		Repr(TypeName(v)))
}

// parseIntLiteral is int(str) in base 10: surrounding whitespace, an optional
// sign, Unicode decimal digits and single underscores between digits.
func parseIntLiteral(s string) (int64, error) {
	bad := func() (int64, error) {
		return 0, valueError("invalid literal for int() with base 10: " + Repr(s))
	}
	body := Strip(s)
	neg := false
	if body != "" && (body[0] == '+' || body[0] == '-') {
		neg = body[0] == '-'
		body = body[1:]
	}
	if body == "" {
		return bad()
	}
	var digits strings.Builder
	prevDigit := false
	for _, r := range body {
		switch {
		case r == '_':
			if !prevDigit {
				return bad()
			}
			prevDigit = false
		case unicode.IsDigit(r):
			digits.WriteByte(byte('0' + DigitValue(r)))
			prevDigit = true
		default:
			return bad()
		}
	}
	if !prevDigit {
		return bad()
	}
	n, err := strconv.ParseUint(digits.String(), 10, 64)
	if err != nil || (!neg && n > math.MaxInt64) || (neg && n > 1<<63) {
		return 0, &Error{Type: "OverflowError", Msg: "integer out of int64 range"}
	}
	if neg {
		return -int64(n), nil
	}
	return int64(n), nil
}

// DigitValue is the decimal value of a Unicode Nd character. Unicode keeps
// each script's digits as a contiguous 0..9 run, so the value is the offset
// from the start of the run, modulo 10 for adjacent runs.
func DigitValue(r rune) int {
	start := r
	for unicode.IsDigit(start - 1) {
		start--
	}
	return int(r-start) % 10
}

// IsSpace is str.isspace() for one character (also what re's \s matches).
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Strip is str.strip() with no arguments.
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Str is str(v) for scalars.
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return FloatRepr(x)
	case string:
		return x
	default:
		return fmt.Sprint(v)
	}
}

// FloatRepr is repr(float): the shortest round-tripping digits, in fixed
// notation for 1e-4 <= |f| < 1e16 (always with a fractional part) and in
// exponent notation otherwise.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	// "-d.dddde±XX": the digits and the decimal exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	sign := ""
	if e[0] == '-' {
		sign, e = "-", e[1:]
	}
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	digits := strings.Replace(mant, ".", "", 1)
	if f == 0 {
		return sign + "0.0"
	}
	decpt := exp + 1 // position of the decimal point within digits
	if decpt > -4 && decpt <= 16 {
		switch {
		case decpt <= 0:
			return sign + "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			return sign + digits[:decpt] + "." + digits[decpt:]
		}
	}
	out := digits[:1]
	if len(digits) > 1 {
		out += "." + digits[1:]
	}
	expSign := "+"
	if exp < 0 {
		expSign, exp = "-", -exp
	}
	return fmt.Sprintf("%s%se%s%02d", sign, out, expSign, exp)
}

// Repr is repr(str).
func Repr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r == ' ' || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// RoundInt is int(round(x)): round half to even, as Python 3 does.
func RoundInt(x float64) int64 { return int64(math.RoundToEven(x)) }

// DivMod is divmod(a, b) for ints: the quotient rounds toward negative
// infinity and the remainder has the sign of b.
func DivMod(a, b int64) (q, r int64) {
	q, r = a/b, a%b
	if r != 0 && (r < 0) != (b < 0) {
		q--
		r += b
	}
	return q, r
}

// DecodeJSON parses JSON the way json.loads does, keeping integers (no '.',
// 'e' or 'E') as int64 and other numbers as float64.
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return FromJSON(v), nil
}

// FromJSON converts a value decoded with json.Decoder.UseNumber into this
// package's representation.
func FromJSON(v any) any {
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				return n
			}
		}
		f, _ := strconv.ParseFloat(s, 64)
		return f
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = FromJSON(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = FromJSON(e)
		}
		return out
	default:
		return v
	}
}
