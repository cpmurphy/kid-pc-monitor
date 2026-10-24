// Package dispatcher executes validated agent protocol requests against a
// Control: it turns "set daily_limit 90" into the right calls and the response
// content the panel expects.
//
// It is a port of src/kid_pc_monitor/request_dispatcher.py.
// testdata/dispatcher/vectors.json is generated from the Python implementation
// by driving it against a recording fake; vectors_test.go replays the same
// requests against a Go fake and checks both the response and the calls made.
//
// # Validation
//
//   - Times are H:MM or HH:MM strings.
//   - Numbers are whole: an int or a decimal string, within ±2^53.
//   - daily_limit and extend take 1–1440 minutes; shutdown takes 0 or more
//     seconds.
//   - manual_lock takes true/false, 1/0, or the words true/yes/1 and
//     false/no/0 in any case.
//   - message takes non-empty text.
package dispatcher

import (
	"fmt"
	"math"
	"strings"
	"unicode"

	"kidpcmonitor/policy"
	"kidpcmonitor/protocol"
)

// Control is the part of the monitoring agent the dispatcher drives.
//
// The Set/Clear/Engage/Extend methods change in-memory state only; the
// dispatcher calls SaveState afterwards, exactly once per successful write.
type Control interface {
	// Reads.
	Hostname() string
	CurrentUser() string
	ScreenLocked() bool
	DailyAllowance() *int64 // minutes; nil: no cap
	BedTime() *policy.TimeOfDay
	WakeTime() policy.TimeOfDay
	ManualLockActive() bool
	CumulativeExtensionSeconds() int64
	AccumulatedSeconds() float64
	TimeRemainingMinutes() (minutes float64, ok bool)
	EnforcementLockState() (active bool, reason string)
	AccessStatus() string
	AgentLogPath() string
	// ReadLogTail returns up to tail lines from the end of the agent log and
	// whether older lines exist.
	ReadLogTail(tail int64) (lines []string, truncated bool, err error)

	// Actions.
	SetDailyAllowance(minutes *int64)
	SetBedTime(hour, minute int)
	ClearBedTime()
	ClearWarnings() // forget which low-time warnings were already sent
	SetWakeTime(hour, minute int)
	EngageManualLock()
	ClearManualLock()
	ClearExtensions()
	ExtendTime(minutes int64)
	// SendParentMessage shows a popup; its failure is reported to the parent
	// as an internal error (the popup is the whole point of the request).
	SendParentMessage(text string) error
	ShutdownPC(seconds int64)
	SaveState()
}

// Handler adapts c to the dispatcher signature protocol.HandleRequest expects.
func Handler(c Control) protocol.Dispatcher {
	return func(req *protocol.Request) ([]protocol.Node, error) { return Dispatch(c, req) }
}

func pyStr(p *string) string {
	if p == nil {
		return "None"
	}
	return *p
}

func isWritable(name string) bool  { return protocol.WritableVariables[name] }
func isClearable(name string) bool { return protocol.ClearableVariables[name] }

func fail(code, message string, req *protocol.Request) error {
	return &protocol.ProtocolError{Code: code, Message: message, ReqID: req.ID}
}

func formatTime(t *policy.TimeOfDay) protocol.Value {
	if t == nil {
		return nil
	}
	return t.String()
}

// parseHHMM mirrors _parse_hhmm.
func parseHHMM(raw protocol.Value, req *protocol.Request) (hour, minute int, err error) {
	s, ok := raw.(string)
	if !ok {
		return 0, 0, fail(protocol.InvalidValue, "time must be HH:MM", req)
	}
	t, perr := policy.ParseTimeHHMM(s)
	if perr != nil {
		return 0, 0, fail(protocol.InvalidValue, "time must be HH:MM (00:00–23:59)", req)
	}
	return t.Hour, t.Minute, nil
}

// parseBool mirrors _parse_bool.
func parseBool(raw protocol.Value, req *protocol.Request) (bool, error) {
	var text string
	switch x := raw.(type) {
	case bool:
		return x, nil
	case int64:
		text = fmt.Sprint(x)
	case string:
		text = strings.ToLower(strings.TrimFunc(x, isPySpace))
	}
	switch text {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	}
	return false, fail(protocol.InvalidValue, "expected a boolean", req)
}

func isPySpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// readVariable mirrors _read_variable.
func readVariable(c Control, name string) (protocol.Value, error) {
	switch name {
	case "name":
		return c.Hostname(), nil
	case "status":
		if c.ScreenLocked() {
			return "LOCKED", nil
		}
		return "UNLOCKED", nil
	case "current_user":
		return c.CurrentUser(), nil
	case "daily_limit":
		if a := c.DailyAllowance(); a != nil {
			return *a, nil
		}
		return nil, nil
	case "bed_time":
		return formatTime(c.BedTime()), nil
	case "manual_lock":
		return c.ManualLockActive(), nil
	case "wake_time":
		w := c.WakeTime()
		return w.String(), nil
	case "cumulative_extension":
		return c.CumulativeExtensionSeconds(), nil
	case "accumulated_seconds":
		return int64(c.AccumulatedSeconds()), nil // truncates, like int()
	case "time_remaining":
		if m, ok := c.TimeRemainingMinutes(); ok {
			return int64(math.RoundToEven(m)), nil // Python's round() rounds half to even
		}
		return nil, nil
	case "enforcement_active":
		active, _ := c.EnforcementLockState()
		return active, nil
	case "enforcement_reason":
		if active, reason := c.EnforcementLockState(); active {
			return reason, nil
		}
		return nil, nil
	case "access_status":
		return c.AccessStatus(), nil
	}
	return nil, &protocol.ProtocolError{Code: protocol.UnknownVariable, Message: "unknown variable: " + name}
}

func doGet(c Control, req *protocol.Request) ([]protocol.Node, error) {
	if req.Var != nil && *req.Var == "settings" {
		settings := protocol.Node{Name: "settings"}
		for _, v := range protocol.Variables {
			value, err := readVariable(c, v.Name)
			if err != nil {
				return nil, err
			}
			settings.Children = append(settings.Children, protocol.N(v.Name, value))
		}
		return protocol.BlockContent(settings), nil
	}
	value, err := readVariable(c, pyStr(req.Var))
	if err != nil {
		return nil, err
	}
	return protocol.OKContent(value), nil
}

func doSet(c Control, req *protocol.Request) ([]protocol.Node, error) {
	name := pyStr(req.Var)
	if req.Var == nil || !isWritable(name) {
		return nil, fail(protocol.Forbidden, name+" is read-only", req)
	}
	var result protocol.Value
	switch name {
	case "daily_limit":
		minutes, err := protocol.ParseInt(req.Val, req.ID)
		if err != nil {
			return nil, err
		}
		if minutes < protocol.MinDailyLimit || minutes > protocol.MaxDailyLimit {
			return nil, fail(protocol.InvalidValue, rangeMessage(), req)
		}
		c.SetDailyAllowance(&minutes)
		result = minutes
	case "bed_time", "wake_time":
		hour, minute, err := parseHHMM(req.Val, req)
		if err != nil {
			return nil, err
		}
		if name == "bed_time" {
			c.SetBedTime(hour, minute)
		} else {
			c.SetWakeTime(hour, minute)
		}
		result = fmt.Sprintf("%02d:%02d", hour, minute)
	default: // manual_lock
		engaged, err := parseBool(req.Val, req)
		if err != nil {
			return nil, err
		}
		if engaged {
			c.EngageManualLock()
		} else {
			c.ClearManualLock()
		}
		result = engaged
	}
	c.SaveState()
	return protocol.OKContent(result), nil
}

func rangeMessage() string {
	return fmt.Sprintf("minutes must be between %d and %d", protocol.MinDailyLimit, protocol.MaxDailyLimit)
}

func doClear(c Control, req *protocol.Request) ([]protocol.Node, error) {
	name := pyStr(req.Var)
	if req.Var == nil || !isClearable(name) {
		return nil, fail(protocol.Forbidden, name+" cannot be cleared", req)
	}
	switch name {
	case "daily_limit":
		c.SetDailyAllowance(nil)
	case "bed_time":
		c.ClearBedTime()
		c.ClearWarnings()
	case "cumulative_extension":
		c.ClearExtensions()
	default: // manual_lock
		c.ClearManualLock()
	}
	c.SaveState()
	return protocol.OKContent("cleared"), nil
}

func doExtend(c Control, req *protocol.Request) ([]protocol.Node, error) {
	minutes, err := protocol.ParseInt(req.Val, req.ID)
	if err != nil {
		return nil, err
	}
	if minutes < protocol.MinDailyLimit || minutes > protocol.MaxDailyLimit {
		return nil, fail(protocol.InvalidValue, rangeMessage(), req)
	}
	c.ExtendTime(minutes)
	c.SaveState()
	return protocol.OKContent(minutes), nil
}

func doMessage(c Control, req *protocol.Request) ([]protocol.Node, error) {
	text, ok := req.Val.(string)
	if !ok || strings.TrimFunc(text, isPySpace) == "" {
		return nil, fail(protocol.InvalidValue, "message must be non-empty text", req)
	}
	if err := c.SendParentMessage(text); err != nil {
		return nil, err
	}
	return protocol.OKContent("message sent"), nil
}

func doShutdown(c Control, req *protocol.Request) ([]protocol.Node, error) {
	seconds := int64(protocol.DefaultShutdownSeconds)
	if req.Val != nil {
		var err error
		if seconds, err = protocol.ParseInt(req.Val, req.ID); err != nil {
			return nil, err
		}
	}
	if seconds < 0 {
		return nil, fail(protocol.InvalidValue, "seconds must not be negative", req)
	}
	c.ShutdownPC(seconds)
	return protocol.OKContent(seconds), nil
}

// logsEnvelopeSize estimates the UTF-8 size of a signed response carrying a
// logs block with the given path and no lines. (The auth block is a stand-in
// without algorithm and key_id; the frame cap's 1 KiB margin covers them.)
func logsEnvelopeSize(path string, truncated bool) int {
	logs := protocol.Block("logs",
		protocol.N("path", path),
		protocol.N("truncated", truncated),
		protocol.N("lines"),
	)
	nodes := []protocol.Node{
		protocol.N("v", 3),
		protocol.N("name", "hostname"),
		protocol.N("timestamp", 0),
		protocol.N("nonce", strings.Repeat("a", 32)),
	}
	nodes = append(nodes, protocol.BlockContent(logs)...)
	nodes = append(nodes, protocol.Block("auth", protocol.N("signature", strings.Repeat("x", 43))))
	return len(protocol.Serialize(nodes))
}

// fitLogLines drops the oldest lines until the logs block fits under the frame
// cap. Each line adds a space plus its serialized token, so one pass over the
// per-line costs finds the same cut as re-serializing after every drop. The
// first drop sets truncated, and "true" is a byte shorter than "false".
func fitLogLines(path string, lines []string, truncated bool) ([]string, bool) {
	budget := protocol.MaxFrameBytes - 1024
	costs := make([]int, len(lines))
	size := logsEnvelopeSize(path, truncated)
	for i, line := range lines {
		costs[i] = 1 + len(protocol.FormatValue(line))
		size += costs[i]
	}
	drop := 0
	for drop < len(lines) && size > budget {
		size -= costs[drop]
		if !truncated {
			truncated = true
			size += logsEnvelopeSize(path, true) - logsEnvelopeSize(path, false)
		}
		drop++
	}
	return lines[drop:], truncated
}

func doGetLogs(c Control, req *protocol.Request) ([]protocol.Node, error) {
	tail := int64(protocol.DefaultLogTailLines)
	if req.Tail != nil {
		tail = *req.Tail
	}
	lines, truncated, err := c.ReadLogTail(tail)
	if err != nil {
		return nil, fail(protocol.Forbidden, "cannot read log file: "+err.Error(), req)
	}
	path := c.AgentLogPath()
	lines, truncated = fitLogLines(path, lines, truncated)
	args := make([]protocol.Value, len(lines))
	for i, l := range lines {
		args[i] = l
	}
	return protocol.BlockContent(protocol.Block("logs",
		protocol.N("path", path),
		protocol.N("truncated", truncated),
		protocol.N("lines", args...),
	)), nil
}

// Dispatch executes a validated request against c and returns the response
// content nodes (a status plus any payload); protocol.HandleRequest wraps them
// in the signed envelope. A *protocol.ProtocolError carries the failure code.
func Dispatch(c Control, req *protocol.Request) ([]protocol.Node, error) {
	switch req.Action {
	case "list_capabilities":
		return protocol.CapabilitiesContent(), nil
	case "get_logs":
		return doGetLogs(c, req)
	case "get":
		return doGet(c, req)
	case "set":
		return doSet(c, req)
	case "clear":
		return doClear(c, req)
	case "extend":
		return doExtend(c, req)
	case "message":
		return doMessage(c, req)
	case "shutdown":
		return doShutdown(c, req)
	case "lock":
		c.EngageManualLock()
		c.SaveState()
		return protocol.OKContent("locked"), nil
	case "unlock":
		c.ClearManualLock()
		c.SaveState()
		return protocol.OKContent("unlocked"), nil
	}
	return nil, &protocol.ProtocolError{
		Code: protocol.UnknownAction, Message: "unknown action: " + req.Action, ReqID: req.ID,
	}
}
