// Package protocol implements the Kid PC Monitor agent wire protocol (v3).
//
// It is a port of the original Python agent_protocol.py and agent_auth.py.
// testdata/protocol/vectors.json is the checked-in contract from that port
// and vectors_test.go checks that this package agrees on every case.
//
// The protocol is a length-prefixed body written in a small subset of KDL,
// where every frame carries an HMAC-SHA256 "auth" block. See
// docs/agent-protocol.md for the specification.
//
// # Values
//
// A KDL scalar is a Value: nil, bool, int64 or string.
//
// # Known differences from the Python implementation
//
//   - A frame body that is not valid UTF-8 is invalid_request; Python raises
//     UnicodeDecodeError.
//   - Error message text for invalid_request/unknown_action may differ in
//     detail (for example Python's repr() of odd values). Error codes and
//     request ids always agree; the vectors check those.
//
// Integers are plain ASCII decimal (optional sign) within 64 bits in the
// document and within ±2^53 as request fields; both implementations enforce
// the same rules.
package protocol
