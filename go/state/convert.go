package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxAbsInt bounds whole numbers read from files, so they are exact in a
// float64 and fit every implementation's integers.
const maxAbsInt = 1 << 53

var errNotObject = errors.New("not a JSON object")

// Document is a decoded JSON object. Numbers are json.Number so integers and
// floats stay distinguishable, as in Python's json module.
type Document = map[string]any

// DecodeDocument decodes one JSON object. A leading UTF-8 byte-order mark is
// accepted. Anything else that is not a single, valid JSON object (including
// NaN and Infinity, and invalid UTF-8) is an error.
func DecodeDocument(raw []byte) (Document, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(raw) {
		return nil, errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errNotObject
	}
	return doc, nil
}

func isFloatForm(n json.Number) bool { return strings.ContainsAny(string(n), ".eE") }

func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

func allASCIIDigits(s string) bool {
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

// toInt reads a whole number: an integer, an integral float, or a decimal
// string. Booleans, fractions and anything beyond ±2^53 are rejected.
func toInt(v any, field string) (int64, error) {
	var n int64
	switch x := v.(type) {
	case json.Number:
		if isFloatForm(x) {
			f, err := strconv.ParseFloat(string(x), 64)
			if err != nil || math.IsInf(f, 0) || f != math.Floor(f) || math.Abs(f) > maxAbsInt {
				return 0, valueErrorf("%s must be a whole number", field)
			}
			n = int64(f)
		} else {
			parsed, err := strconv.ParseInt(string(x), 10, 64)
			if err != nil {
				return 0, valueErrorf("%s is out of range", field)
			}
			n = parsed
		}
	case string:
		text := strings.TrimFunc(x, isSpace)
		digits := strings.TrimLeft(text, "+-")
		if len(text)-len(digits) > 1 || !allASCIIDigits(digits) {
			return 0, valueErrorf("%s must be a whole number", field)
		}
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, valueErrorf("%s is out of range", field)
		}
		n = parsed
	default:
		return 0, valueErrorf("%s must be a whole number", field)
	}
	if n > maxAbsInt || n < -maxAbsInt {
		return 0, valueErrorf("%s is out of range", field)
	}
	return n, nil
}

func toNonNegInt(v any, field string) (int64, error) {
	n, err := toInt(v, field)
	if err == nil && n < 0 {
		return 0, valueErrorf("%s must not be negative", field)
	}
	return n, err
}

// matchDecimal reports whether s is [+-]?(digits[.digits?]|.digits)([eE][+-]?digits)?.
func matchDecimal(s string) bool {
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	intDigits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		intDigits++
	}
	fracDigits := 0
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			fracDigits++
		}
	}
	if intDigits == 0 && fracDigits == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		expDigits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			expDigits++
		}
		if expDigits == 0 {
			return false
		}
	}
	return i == len(s)
}

// toNonNegFloat reads a finite, non-negative number: a number or a decimal string.
func toNonNegFloat(v any, field string) (float64, error) {
	var f float64
	switch x := v.(type) {
	case json.Number:
		if !isFloatForm(x) {
			n, err := strconv.ParseInt(string(x), 10, 64)
			if err != nil || n > maxAbsInt || n < -maxAbsInt {
				return 0, valueErrorf("%s is out of range", field)
			}
			f = float64(n)
		} else {
			parsed, err := strconv.ParseFloat(string(x), 64)
			if err != nil {
				return 0, valueErrorf("%s must be a finite, non-negative number", field)
			}
			f = parsed
		}
	case string:
		text := strings.TrimFunc(x, isSpace)
		if !matchDecimal(text) {
			return 0, valueErrorf("%s must be a number", field)
		}
		parsed, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, valueErrorf("%s must be a finite, non-negative number", field)
		}
		f = parsed
	default:
		return 0, valueErrorf("%s must be a number", field)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
		return 0, valueErrorf("%s must be a finite, non-negative number", field)
	}
	return f, nil
}

// toBool reads a JSON boolean; 0, 1, "true" and "false" are tolerated for
// hand-edited files.
func toBool(v any, field string) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case json.Number:
		if !isFloatForm(x) {
			switch string(x) {
			case "0", "-0":
				return false, nil
			case "1":
				return true, nil
			}
		}
	case string:
		switch strings.ToLower(strings.TrimFunc(x, isSpace)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, valueErrorf("%s must be true or false", field)
}
