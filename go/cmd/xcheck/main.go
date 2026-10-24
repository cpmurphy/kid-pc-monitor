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

	"kidpcmonitor/protocol"
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
	_ = fs.Parse(os.Args[2:])
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

type toyAgent struct {
	hostname    string
	dailyLimit  int64
	bedTime     string
	wakeTime    string
	manualLock  bool
	extension   int64
	accumulated int64
	messages    []string
}

func (a *toyAgent) settings() protocol.Node {
	status := "UNLOCKED"
	access := "Unlocked"
	if a.manualLock {
		status, access = "LOCKED", "Locked — manual lock"
	}
	return protocol.Block("settings",
		protocol.N("name", a.hostname),
		protocol.N("status", status),
		protocol.N("current_user", "kid"),
		protocol.N("daily_limit", a.dailyLimit),
		protocol.N("bed_time", a.bedTime),
		protocol.N("manual_lock", a.manualLock),
		protocol.N("wake_time", a.wakeTime),
		protocol.N("cumulative_extension", a.extension),
		protocol.N("accumulated_seconds", a.accumulated),
		protocol.N("time_remaining", nil),
		protocol.N("enforcement_active", a.manualLock),
		protocol.N("enforcement_reason", nil),
		protocol.N("access_status", access),
	)
}

func (a *toyAgent) get(variable string) (protocol.Value, bool) {
	s := a.settings().ChildMap()
	v, ok := s[variable]
	return v, ok
}

func invalid(req *protocol.Request, msg string) error {
	return &protocol.ProtocolError{Code: protocol.InvalidValue, Message: msg, ReqID: req.ID}
}

func asInt(v protocol.Value) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

func (a *toyAgent) dispatch(req *protocol.Request) ([]protocol.Node, error) {
	switch req.Action {
	case "list_capabilities":
		return protocol.CapabilitiesContent(), nil
	case "get":
		if *req.Var == "settings" {
			return protocol.BlockContent(a.settings()), nil
		}
		v, _ := a.get(*req.Var)
		return protocol.OKContent(v), nil
	case "set":
		return a.set(req)
	case "clear":
		switch *req.Var {
		case "daily_limit":
			a.dailyLimit = 120
		case "bed_time":
			a.bedTime = "21:00"
		case "manual_lock":
			a.manualLock = false
		case "cumulative_extension":
			a.extension = 0
		default:
			return nil, invalid(req, *req.Var+" cannot be cleared")
		}
		return protocol.OKContent("cleared"), nil
	case "lock":
		a.manualLock = true
		return protocol.OKContent("locked"), nil
	case "unlock":
		a.manualLock = false
		return protocol.OKContent("unlocked"), nil
	case "extend":
		minutes, ok := asInt(req.Val)
		if !ok || minutes <= 0 {
			return nil, invalid(req, "minutes must be a positive number")
		}
		a.extension += minutes * 60
		return protocol.OKContent(minutes), nil
	case "message":
		text, ok := req.Val.(string)
		if !ok {
			return nil, invalid(req, "message must be text")
		}
		a.messages = append(a.messages, text)
		return protocol.OKContent(text), nil // echoed so the peer can check the escaping
	case "shutdown":
		seconds := int64(protocol.DefaultShutdownSeconds)
		if req.Val != nil {
			var ok bool
			if seconds, ok = asInt(req.Val); !ok || seconds < 0 {
				return nil, invalid(req, "seconds must not be negative")
			}
		}
		return protocol.OKContent(seconds), nil
	case "get_logs":
		tail := int64(protocol.DefaultLogTailLines)
		if req.Tail != nil {
			tail = *req.Tail
		}
		all := logLines(10)
		truncated := tail < int64(len(all))
		if truncated {
			all = all[int64(len(all))-tail:]
		}
		lines := make([]protocol.Value, len(all))
		for i, l := range all {
			lines[i] = l
		}
		return protocol.BlockContent(protocol.Block("logs",
			protocol.N("path", `C:\ProgramData\KidPCMonitor\pc_control.log`),
			protocol.N("truncated", truncated),
			protocol.N("lines", lines...),
		)), nil
	}
	return nil, &protocol.ProtocolError{Code: protocol.UnknownAction, Message: req.Action, ReqID: req.ID}
}

func logLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf(`[2026-05-31 12:00:%02d] INFO kid_pc_monitor: line %d "quoted" \ ünï`, i, i)
	}
	return lines
}

func (a *toyAgent) set(req *protocol.Request) ([]protocol.Node, error) {
	switch *req.Var {
	case "daily_limit":
		n, ok := asInt(req.Val)
		if !ok || n < protocol.MinDailyLimit || n > protocol.MaxDailyLimit {
			return nil, invalid(req, fmt.Sprintf("minutes must be between %d and %d",
				protocol.MinDailyLimit, protocol.MaxDailyLimit))
		}
		a.dailyLimit = n
	case "bed_time", "wake_time":
		s, ok := req.Val.(string)
		if !ok {
			return nil, invalid(req, "expected a HH:MM time")
		}
		if *req.Var == "bed_time" {
			a.bedTime = s
		} else {
			a.wakeTime = s
		}
	case "manual_lock":
		b, ok := req.Val.(bool)
		if !ok {
			return nil, invalid(req, "expected true or false")
		}
		a.manualLock = b
	default:
		return nil, &protocol.ProtocolError{
			Code: protocol.Forbidden, Message: *req.Var + " is read-only", ReqID: req.ID,
		}
	}
	return protocol.OKContent(req.Val), nil
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
	agent := &toyAgent{
		hostname: hostname, dailyLimit: 120, bedTime: "21:00", wakeTime: "07:00", accumulated: 1234,
	}
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
		resp := protocol.HandleRequest(body, secret, hostname, time.Now().Unix(), agent.dispatch)
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
