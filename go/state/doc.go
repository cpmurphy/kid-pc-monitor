// Package state reads and writes the agent's persistent settings and runtime
// state: daily_settings.json (bed time, wake time, allowance) and state.json
// (usage so far today, manual lock, extensions).
//
// It is a port of src/kid_pc_monitor/agent_state.py. testdata/state/vectors.json
// is generated from the Python implementation and vectors_test.go checks that
// this package agrees on every case, so a Go agent can take over the files a
// Python agent wrote and vice versa.
//
// # Files are never silently discarded
//
// A file that exists but cannot be used (not UTF-8, not JSON, NaN/Infinity,
// not an object, or holding an invalid value) is renamed to
// <name>.corrupt-<timestamp>, and the last good copy, <name>.bak, is restored
// in its place. Every Save refreshes the backup, but only from a file that
// itself validates. Only if there is no usable backup do defaults apply, and
// the corrupt file stays on disk for the parent to inspect. A file that has
// merely gone missing is restored from its backup too. Store.Problems lists
// what happened.
//
// A file that could not be read at all (permission denied, in use by another
// program) says nothing about its content, so Load returns that error instead
// of touching anything. Callers must not Save after a failed Load.
//
// # Strict values
//
// Values are validated, not coerced, and every invalid value is a *ValueError:
//
//   - times are H:MM or HH:MM strings;
//   - allowance and extension seconds are whole numbers (an integer, an
//     integral float such as 90.0, or a decimal string), never booleans, and
//     not negative or beyond ±2^53;
//   - accumulated seconds is a finite, non-negative number or decimal string;
//   - manual_lock_active is true/false (0, 1, "true" and "false" are
//     tolerated), never merely "truthy";
//   - timestamps follow an explicit ISO 8601 grammar (see ParseISODatetime)
//     and are naive wall-clock times: any UTC offset is dropped.
//
// A legacy pc_control_state.json is only consulted when there is no usable
// daily_settings.json, and never overwrites one.
//
// # Known limits
//
// A JSON document nested more than about a thousand levels deep is rejected by
// Python's parser but accepted by Go's; no version of the agent writes one.
package state
