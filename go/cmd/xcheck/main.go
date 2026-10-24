// Command xcheck is the Go half of scripts/cross_check_go.py.
//
// It plays either end of a reverse session so the Python implementation can be
// driven against it over a real TCP socket:
//
//	xcheck agent -connect host:port -secret S -hostname H
//	    a toy agent that dials the panel and answers requests
//	xcheck panel -listen 127.0.0.1:0 -secret S
//	    a toy panel that waits for an agent and runs a scripted conversation,
//	    printing one JSON line per step
//	xcheck state-write -dir D -now ISO
//	    save a fixed sample of settings and runtime state into D
//	xcheck state-dump -dir D -now ISO -user U
//	    load D with the state package and print what it found as JSON
//
// It is a test fixture, not a deliverable: the toy agent keeps its settings in
// memory and does not touch the host.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"kidpcmonitor/dispatcher"
	"kidpcmonitor/policy"
	"kidpcmonitor/protocol"
	"kidpcmonitor/state"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: xcheck agent|panel [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	secret := fs.String("secret", "", "shared secret")
	connect := fs.String("connect", "", "agent: panel address to dial")
	hostname := fs.String("hostname", "go-kid-pc", "agent: hostname to claim")
	listen := fs.String("listen", "127.0.0.1:0", "panel: address to listen on")
	dir := fs.String("dir", "", "state-*: agent data directory")
	nowFlag := fs.String("now", "", "state-*: fake wall-clock time (ISO 8601)")
	user := fs.String("user", "kid", "state-dump: account the agent runs as")
	_ = fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "state-write":
		runStateWrite(*dir, *nowFlag)
		return
	case "state-dump":
		runStateDump(*dir, *nowFlag, *user)
		return
	}
	if *secret == "" {
		fatalf("-secret is required")
	}
	switch os.Args[1] {
	case "agent":
		runAgent(*connect, *secret, *hostname)
	case "panel":
		runPanel(*listen, *secret)
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "xcheck: "+format+"\n", args...)
	os.Exit(2)
}

// ---------------------------------------------------------------------------
// Toy agent
// ---------------------------------------------------------------------------

// toyControl is an in-memory dispatcher.Control: it keeps settings in memory
// and touches nothing on the host.
type toyControl struct {
	hostname    string
	allowance   *int64
	bedTime     *policy.TimeOfDay
	wakeTime    policy.TimeOfDay
	manualLock  bool
	extension   int64
	accumulated float64
	messages    []string
}

func (c *toyControl) Hostname() string                      { return c.hostname }
func (c *toyControl) CurrentUser() string                   { return "kid" }
func (c *toyControl) ScreenLocked() bool                    { return c.manualLock }
func (c *toyControl) DailyAllowance() *int64                { return c.allowance }
func (c *toyControl) BedTime() *policy.TimeOfDay            { return c.bedTime }
func (c *toyControl) WakeTime() policy.TimeOfDay            { return c.wakeTime }
func (c *toyControl) ManualLockActive() bool                { return c.manualLock }
func (c *toyControl) CumulativeExtensionSeconds() int64     { return c.extension }
func (c *toyControl) AccumulatedSeconds() float64           { return c.accumulated }
func (c *toyControl) TimeRemainingMinutes() (float64, bool) { return 0, false }
func (c *toyControl) AgentLogPath() string                  { return `C:\ProgramData\KidPCMonitor\pc_control.log` }
func (c *toyControl) AccessStatus() string {
	if c.manualLock {
		return "Locked — manual lock"
	}
	return "Unlocked"
}
func (c *toyControl) EnforcementLockState() (bool, string) { return false, "" }

func (c *toyControl) ReadLogTail(tail int64) ([]string, bool, error) {
	all := logLines(10)
	if tail >= int64(len(all)) {
		return all, false, nil
	}
	return all[int64(len(all))-tail:], true, nil
}

func (c *toyControl) SetDailyAllowance(m *int64) { c.allowance = m }
func (c *toyControl) SetBedTime(h, m int)        { c.bedTime = policy.At(h, m) }
func (c *toyControl) ClearBedTime()              { c.bedTime = nil }
func (c *toyControl) ClearWarnings()             {}
func (c *toyControl) SetWakeTime(h, m int)       { c.wakeTime = policy.TimeOfDay{Hour: h, Minute: m} }
func (c *toyControl) EngageManualLock()          { c.manualLock = true }
func (c *toyControl) ClearManualLock()           { c.manualLock = false }
func (c *toyControl) ClearExtensions()           { c.extension = 0 }
func (c *toyControl) ExtendTime(minutes int64)   { c.extension += minutes * 60; c.manualLock = false }
func (c *toyControl) SendParentMessage(t string) error {
	c.messages = append(c.messages, t)
	return nil
}
func (c *toyControl) ShutdownPC(seconds int64) {}
func (c *toyControl) SaveState()               {}

func logLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf(`[2026-05-31 12:00:%02d] INFO kid_pc_monitor: line %d "quoted" \ ünï`, i, i)
	}
	return lines
}

func runAgent(addr, secret, hostname string) {
	if addr == "" {
		fatalf("agent mode needs -connect")
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer conn.Close()
	allowance := int64(120)
	control := &toyControl{
		hostname: hostname, allowance: &allowance, bedTime: policy.At(21, 0),
		wakeTime: policy.TimeOfDay{Hour: 7}, accumulated: 1234,
	}
	// When the panel hangs up, report the popups the agent was asked to show so
	// the driver can check the text arrived byte for byte.
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(map[string]any{"messages": control.messages}) }()

	dispatch := dispatcher.Handler(control)
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		body, err := protocol.ReadFrame(br)
		if err != nil {
			if protocol.IsClosedBeforeFrame(err) {
				return // panel hung up between requests
			}
			fatalf("read: %v", err)
		}
		resp := protocol.HandleRequest(body, secret, hostname, time.Now().Unix(), dispatch)
		if err := protocol.WriteFrame(conn, resp); err != nil {
			fatalf("write: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Toy panel
// ---------------------------------------------------------------------------

type panel struct {
	conn   net.Conn
	br     *bufio.Reader
	secret string
	name   string
	out    *json.Encoder
	failed bool
}

func (p *panel) send(body string) (string, error) {
	_ = p.conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := protocol.WriteFrame(p.conn, body); err != nil {
		return "", err
	}
	return protocol.ReadFrame(p.br)
}

// record prints one step's outcome for the Python driver.
func (p *panel) record(step, body string, expectedName string) {
	rec := map[string]any{"step": step}
	reply, err := p.send(body)
	if err == nil {
		var resp *protocol.Response
		resp, err = protocol.ParseResponse(reply, p.secret, protocol.ResponseOptions{
			ExpectedName: expectedName, ExpectedVersion: protocol.ProtocolVersion,
		}, time.Now().Unix())
		if err == nil {
			rec["ok"] = resp.OK()
			rec["result"] = resp.Result
			rec["error_code"] = resp.ErrorCode
			rec["name"] = resp.Name
			rec["settings"] = resp.Settings
			if resp.Logs != nil {
				rec["logs"] = map[string]any{
					"path": resp.Logs.Path, "truncated": resp.Logs.Truncated, "lines": resp.Logs.Lines,
				}
			}
		}
	}
	if err != nil {
		rec["ok"] = false
		rec["local_error"] = err.Error()
		p.failed = true
	}
	_ = p.out.Encode(rec)
}

func (p *panel) request(step string, params protocol.RequestParams) {
	params.Secret = p.secret
	if params.ReqID == "" {
		params.ReqID = strings.ToLower(protocol.MakeNonce()[:6])
	}
	if params.Name == "" && protocol.WriteActions[params.Action] {
		params.Name = p.name
	}
	body, err := protocol.BuildRequest(params)
	if err != nil {
		fatalf("%s: %v", step, err)
	}
	p.record(step, body, p.name)
}

func (p *panel) raw(step, body string) { p.record(step, body, "") }

func runPanel(addr, secret string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatalf("listen: %v", err)
	}
	fmt.Printf("LISTENING %d\n", ln.Addr().(*net.TCPAddr).Port)
	_ = os.Stdout.Sync()
	if tcp, ok := ln.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(60 * time.Second))
	}
	conn, err := ln.Accept()
	if err != nil {
		fatalf("accept: %v", err)
	}
	defer conn.Close()
	p := &panel{conn: conn, br: bufio.NewReader(conn), secret: secret, out: json.NewEncoder(os.Stdout)}

	// Discovery: an unnamed read teaches the panel the agent's hostname.
	body, _ := protocol.BuildRequest(protocol.RequestParams{
		Action: "get", Var: "settings", Secret: secret, ReqID: "disc",
	})
	reply, err := p.send(body)
	if err != nil {
		fatalf("discovery: %v", err)
	}
	resp, err := protocol.ParseResponse(reply, secret, protocol.ResponseOptions{}, time.Now().Unix())
	if err != nil || resp.Name == nil {
		fatalf("discovery reply: %v", err)
	}
	p.name = *resp.Name
	_ = p.out.Encode(map[string]any{"step": "discover", "ok": resp.OK(), "name": p.name, "settings": resp.Settings})

	p.request("get_name", protocol.RequestParams{Action: "get", Var: "name"})
	p.request("list_capabilities", protocol.RequestParams{Action: "list_capabilities"})
	p.request("lock", protocol.RequestParams{Action: "lock"})
	p.request("get_manual_lock_after_lock", protocol.RequestParams{Action: "get", Var: "manual_lock"})
	p.request("unlock", protocol.RequestParams{Action: "unlock"})
	p.request("set_daily_limit", protocol.RequestParams{Action: "set", Var: "daily_limit", Val: 90})
	p.request("get_daily_limit", protocol.RequestParams{Action: "get", Var: "daily_limit"})
	p.request("set_daily_limit_too_big", protocol.RequestParams{Action: "set", Var: "daily_limit", Val: 99999})
	p.request("set_bed_time", protocol.RequestParams{Action: "set", Var: "bed_time", Val: "21:30"})
	p.request("get_bed_time", protocol.RequestParams{Action: "get", Var: "bed_time"})
	p.request("extend", protocol.RequestParams{Action: "extend", Val: 15})
	p.request("message", protocol.RequestParams{Action: "message", Val: messageText})
	p.request("get_logs_tail_3", protocol.RequestParams{Action: "get_logs", Tail: 3})
	p.request("get_unknown_variable", protocol.RequestParams{Action: "get", Var: "nope"})
	p.request("shutdown_negative", protocol.RequestParams{Action: "shutdown", Val: -1})

	now := time.Now().Unix()
	p.raw("wrong_secret", mustBuild(protocol.RequestParams{
		Action: "get", Var: "name", Secret: "not-the-secret", ReqID: "ws",
	}))
	p.raw("stale_timestamp", mustBuild(protocol.RequestParams{
		Action: "get", Var: "name", Secret: secret, ReqID: "st", Timestamp: now - 3600,
	}))
	p.raw("foreign_name", mustBuild(protocol.RequestParams{
		Action: "lock", Secret: secret, ReqID: "fn", Name: "some-other-pc",
	}))
	p.raw("unnamed_write", mustBuild(protocol.RequestParams{
		Action: "lock", Secret: secret, ReqID: "uw",
	}))
	p.raw("old_protocol_version", "v 2\nid ov\naction get")
	p.raw("not_kdl", "this is {{ not kdl")
	p.raw("hostile_nesting", strings.Repeat("a {", 5000))
	_ = p.out.Encode(map[string]any{"step": "done", "ok": !p.failed})
}

// messageText exercises quoting: quotes, backslashes, tabs, Unicode and a
// trailing newline.
const messageText = "Dinner 🍝 at \"six\"\n\tsee C:\\path\\ ünï\n"

func mustBuild(p protocol.RequestParams) string {
	body, err := protocol.BuildRequest(p)
	if err != nil {
		fatalf("%v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// State files
// ---------------------------------------------------------------------------

func stateStore(dir, nowText, user string) *state.Store {
	now, err := state.ParseISODatetime(nowText)
	if err != nil || dir == "" {
		fatalf("state modes need -dir and a valid -now: %v", err)
	}
	return &state.Store{
		DataDir: dir, CurrentUser: user,
		Clock: func() time.Time { return now },
	}
}

func runStateWrite(dir, nowText string) {
	store := stateStore(dir, nowText, "kid")
	allowance := int64(100)
	daily := state.DailySettings{
		BedTime: policy.At(21, 15), WakeTime: policy.TimeOfDay{Hour: 6, Minute: 30}, Allowance: &allowance,
	}
	runtimeState := state.RuntimeState{
		AccumulatedSeconds: 1234.56789, ManualLockActive: true, CumulativeExtensionSeconds: 300,
	}
	if err := store.Save(daily, &runtimeState); err != nil {
		fatalf("save: %v", err)
	}
}

func runStateDump(dir, nowText, user string) {
	daily, runtimeState, err := stateStore(dir, nowText, user).Load()
	if err != nil {
		fatalf("load: %v", err)
	}
	out := map[string]any{
		"wake_time":                    daily.WakeTime.String(),
		"bed_time":                     nil,
		"allowance":                    nil,
		"timestamp":                    state.FormatISO(runtimeState.Timestamp),
		"accumulated_seconds":          runtimeState.AccumulatedSeconds,
		"manual_lock_active":           runtimeState.ManualLockActive,
		"cumulative_extension_seconds": runtimeState.CumulativeExtensionSeconds,
	}
	if daily.BedTime != nil {
		out["bed_time"] = daily.BedTime.String()
	}
	if daily.Allowance != nil {
		out["allowance"] = *daily.Allowance
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
