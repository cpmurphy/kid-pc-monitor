package protocol

import "errors"

// Error codes (see docs/agent-protocol.md).
const (
	InvalidRequest         = "invalid_request"
	UnsupportedVersion     = "unsupported_version"
	UnknownAction          = "unknown_action"
	UnknownVariable        = "unknown_variable"
	InvalidValue           = "invalid_value"
	Forbidden              = "forbidden"
	InternalError          = "internal_error"
	AuthenticationRequired = "authentication_required"
	AuthenticationFailed   = "authentication_failed"
	StaleTimestamp         = "stale_timestamp"
)

// ProtocolError is a protocol-level failure carrying an error code and
// message. ReqID is the request id to echo in the failure response, if known.
type ProtocolError struct {
	Code    string
	Message string
	ReqID   *string
	// ClosedBeforeFrame marks a peer that disconnected without sending any
	// frame bytes: what a bare TCP liveness probe looks like. It is benign.
	ClosedBeforeFrame bool
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Message }

func perr(code, message string, reqID *string) *ProtocolError {
	return &ProtocolError{Code: code, Message: message, ReqID: reqID}
}

// IsClosedBeforeFrame reports whether err is a ProtocolError for a peer that
// closed the connection before sending anything.
func IsClosedBeforeFrame(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe) && pe.ClosedBeforeFrame
}

// CodeOf returns the protocol error code of err, or "" if it is not a
// ProtocolError.
func CodeOf(err error) string {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
