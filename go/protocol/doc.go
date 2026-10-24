// Package protocol implements the Kid PC Monitor agent wire protocol (v3).
//
// It is a port of src/kid_pc_monitor/agent_protocol.py and agent_auth.py.
// The Python implementation is the reference: testdata/protocol/vectors.json
// is generated from it (tests/protocol_vectors_gen.py) and vectors_test.go
// checks that this package agrees on every case.
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
// Python's int() accepts more spellings than the protocol ever produces
// (Unicode digits, arbitrary-precision integers, 0x-prefixed hex in \u{...}
// escapes). This package is deliberately stricter:
//
//   - A bare integer that does not fit in an int64 is a parse error
//     (invalid_request); Python keeps it as a big integer.
//   - Only ASCII digits are integers; "٣" stays a string.
//   - \u{...} escapes take plain hex digits and reject surrogates.
//   - A frame body that is not valid UTF-8 is invalid_request; Python raises
//     UnicodeDecodeError.
//   - Error message text for invalid_request/unknown_action may differ in
//     detail (for example Python's repr() of odd values). Error codes and
//     request ids always agree; the vectors check those.
//
// None of these can occur in frames produced by either implementation.
package protocol
