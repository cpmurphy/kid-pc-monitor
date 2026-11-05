package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/panel/reverse"
)

// runReversePanel serves panel/reverse on addr and runs commands from stdin:
//
//	{"cmd": "wait_status"}                       first status: {"hostname", "ip", "pc_info"}
//	{"cmd": "action", "ip", "action", "payload"} {"ok", "text", "found"}
//	{"cmd": "logs", "ip", "tail"}                {"lines", "truncated", "path"} or {"error"}
//	{"cmd": "session", "ip"}                     {"hostname", "pc_info"} or {"found": false}
//	{"cmd": "wait_disconnect"}                   {"hostname", "ip"} of the next disconnect
//
// pc_info is format.SettingsToPCInfo of the settings, as the panel stores it.
func runReversePanel(addr, secret string, refresh time.Duration) {
	statuses := make(chan map[string]any, 64)
	disconnects := make(chan map[string]any, 8)
	srv := &reverse.Server{
		Secret:          func() (string, error) { return secret, nil },
		StatusRefresh:   refresh,
		ExchangeTimeout: 15 * time.Second,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnStatus: func(h, ip string, settings map[string]any) {
			info, err := format.SettingsToPCInfo(settings, ip, h)
			rec := map[string]any{"hostname": h, "ip": ip, "pc_info": info}
			if err != nil {
				rec["error"] = err.Error()
			}
			select {
			case statuses <- rec:
			default:
			}
		},
		OnDisconnect: func(h, ip string) { disconnects <- map[string]any{"hostname": h, "ip": ip} },
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)
	fmt.Printf("LISTENING %d\n", ln.Addr().(*net.TCPAddr).Port)
	_ = os.Stdout.Sync()

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for in.Scan() {
		v, err := pyval.DecodeJSON(in.Bytes())
		if err != nil {
			fatalf("bad command %q: %v", in.Text(), err)
		}
		cmd := v.(map[string]any)
		ip, _ := cmd["ip"].(string)
		var rec map[string]any
		switch cmd["cmd"] {
		case "wait_status":
			rec = waitFor(statuses, "status")
		case "wait_disconnect":
			rec = waitFor(disconnects, "disconnect")
		case "action":
			payload, _ := cmd["payload"].(map[string]any)
			name, _ := cmd["action"].(string)
			ok, text, found := srv.PerformAction(ip, name, payload)
			rec = map[string]any{"ok": ok, "text": text, "found": found}
		case "logs":
			tail, _ := cmd["tail"].(int64)
			logs, err := srv.GetLogs(ip, tail)
			if err != nil {
				rec = map[string]any{"error": err.Error()}
			} else {
				rec = map[string]any{"lines": logs.Lines, "truncated": logs.Truncated, "path": logs.Path}
			}
		case "session":
			sess := srv.SessionForIP(ip)
			if sess == nil {
				rec = map[string]any{"found": false}
				break
			}
			info, err := format.SettingsToPCInfo(sess.Settings(), ip, sess.Hostname)
			rec = map[string]any{"hostname": sess.Hostname, "pc_info": info}
			if err != nil {
				rec["error"] = err.Error()
			}
		default:
			fatalf("unknown command %v", cmd["cmd"])
		}
		line, err := pyval.EncodeJSON(rec) // keeps Python's int/float distinction
		if err != nil {
			fatalf("encode %v: %v", rec, err)
		}
		fmt.Println(line)
		_ = os.Stdout.Sync()
	}
}

func waitFor(ch chan map[string]any, what string) map[string]any {
	select {
	case rec := <-ch:
		return rec
	case <-time.After(20 * time.Second):
		return map[string]any{"error": "timed out waiting for " + what}
	}
}
