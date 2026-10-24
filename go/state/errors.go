package state

import (
	"errors"
	"fmt"
)

// ValueError is returned for any invalid value in a state file or legacy
// payload, whatever the reason: wrong type, malformed, or out of range. (It
// mirrors Python's ValueError, which is what the Python implementation raises
// for all of these.)
type ValueError struct{ Msg string }

func (e *ValueError) Error() string { return e.Msg }

func valueErrorf(format string, args ...any) error {
	return &ValueError{fmt.Sprintf(format, args...)}
}

// IsValueError reports whether err is (or wraps) a ValueError.
func IsValueError(err error) bool {
	var ve *ValueError
	return errors.As(err, &ve)
}

// errorClass names the Python exception class an error corresponds to, for the
// golden vectors.
func errorClass(err error) string {
	if IsValueError(err) {
		return "ValueError"
	}
	return "other"
}
