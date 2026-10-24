package state

import (
	"errors"
	"fmt"
)

// ValueError mirrors Python's ValueError: the value has the right type but is
// unusable (bad time, unparsable number).
type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

// TypeError mirrors Python's TypeError: the value has a type the conversion
// does not accept (null, a list or an object where a number is expected).
type TypeError struct{ Msg string }

func (e *TypeError) Error() string { return e.Msg }

func valueErrorf(format string, args ...any) error {
	return &ValueError{fmt.Sprintf(format, args...)}
}

func typeErrorf(format string, args ...any) error {
	return &TypeError{fmt.Sprintf(format, args...)}
}

// IsValueError reports whether err is (or wraps) a ValueError.
func IsValueError(err error) bool {
	var ve *ValueError
	return errors.As(err, &ve)
}

// IsTypeError reports whether err is (or wraps) a TypeError.
func IsTypeError(err error) bool {
	var te *TypeError
	return errors.As(err, &te)
}

// errorClass names the Python exception class an error corresponds to, for the
// golden vectors.
func errorClass(err error) string {
	switch {
	case IsValueError(err):
		return "ValueError"
	case IsTypeError(err):
		return "TypeError"
	}
	return "other"
}
