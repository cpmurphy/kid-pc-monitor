// Package state reads and writes the agent's persistent settings and runtime
// state: daily_settings.json (bed time, wake time, allowance) and state.json
// (usage so far today, manual lock, extensions).
//
// It is a port of src/kid_pc_monitor/agent_state.py. testdata/state/vectors.json
// is generated from the Python implementation and vectors_test.go checks that
// this package agrees on every case, including the quirks listed below, so a
// Go agent can take over the files a Python agent wrote and vice versa.
//
// # Faithfully ported behavior worth knowing
//
//   - A file that is not valid JSON (including one with a UTF-8 byte-order
//     mark, which Notepad adds) is treated as missing, and is overwritten with
//     defaults when nothing else supplies settings.
//   - Loaded values follow Python's conversion rules: allowance "90" and 90.7
//     become 90, and manual_lock_active "false" is true (any non-empty string
//     is).
//   - Failures are classified like Python's exceptions. A ValueError in
//     state.json means "start with a fresh runtime"; a TypeError (for example
//     a null number) or any error in daily_settings.json aborts Load. The
//     caller decides what to do then; Python's agent keeps running with
//     built-in defaults, which means no limits. See IsValueError/IsTypeError.
//   - Reading a legacy pc_control_state.json while only state.json is missing
//     overwrites daily_settings.json with the legacy values.
//
// # Differences from Python
//
// This package is deliberately stricter than Python on inputs the agent never
// writes: integers outside int64, non-finite floats (NaN/Infinity), floats
// written with underscores or in hex, Unicode digits, basic-format or
// week-date ISO timestamps, and ISO date-time separators other than 'T' and
// ' '. A top-level JSON value that is not an object is an error. Time zones in
// timestamps are discarded: only the written wall-clock fields matter.
package state
