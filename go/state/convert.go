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

	"kidpcmonitor/internal/pycompat"
)

var errNotObject = errors.New("top-level JSON value is not an object")

// Document is a decoded JSON object. Numbers are json.Number so integers and
// floats stay distinguishable, as in Python's json module.
type Document = map[string]any

// DecodeDocument decodes one JSON object, rejecting trailing data.
func DecodeDocument(raw []byte) (Document, error) {
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

// toInt mirrors Python's int(x) for a decoded JSON value.
func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case json.Number:
		if !isFloatForm(x) {
			n, err := strconv.ParseInt(string(x), 10, 64)
			if err != nil {
				return 0, valueErrorf("integer %s out of range", x)
			}
			return n, nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) >= 1<<63 {
			return 0, valueErrorf("number %s out of range", x)
		}
		return int64(f), nil // truncates toward zero, like int()
	case string:
		n, st := pycompat.Int(x)
		if st != pycompat.OK {
			return 0, valueErrorf("invalid literal for int(): %q", x)
		}
		return n, nil
	}
	return 0, typeErrorf("int() argument must be a string or a number, not %s", typeName(v))
}

// toFloat mirrors Python's float(x) for a decoded JSON value.
func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, valueErrorf("number %s out of range", x)
		}
		return f, nil
	case string:
		s := strings.TrimFunc(x, isSpace)
		if s == "" || strings.ContainsAny(s, "_xXpP") {
			return 0, valueErrorf("could not convert string to float: %q", x)
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, valueErrorf("could not convert string to float: %q", x)
		}
		return f, nil
	}
	return 0, typeErrorf("float() argument must be a string or a number, not %s", typeName(v))
}

// truthy mirrors Python's bool(x) for a decoded JSON value.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case json.Number:
		f, _ := strconv.ParseFloat(string(x), 64)
		return f != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case []any:
		return "list"
	case map[string]any:
		return "dict"
	}
	return "value"
}

func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}
