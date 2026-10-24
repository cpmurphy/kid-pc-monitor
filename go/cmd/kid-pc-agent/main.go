//go:build windows

// Command kid-pc-agent is the kid-side agent, a port of
// src/kid_pc_monitor/pc_control.py: it logs to
// %LOCALAPPDATA%\KidPCMonitor\pc_control.log (size-rotated), enforces the
// daily limits with the monitoring loop, and keeps a reverse connection open
// to the parent panel until it is interrupted.
//
// Unlike the Python agent, the start-up connectivity diagnostics run in the
// background after enforcement has started, so a slow PowerShell query never
// leaves the PC unenforced at logon.
//
// Build it as a GUI-subsystem program so the scheduled task does not open a
// console window (the Python installer uses pythonw.exe for the same reason):
//
//	go build -ldflags -H=windowsgui -o kid-pc-agent.exe ./cmd/kid-pc-agent
//
// Run from a console (plain go build / go run) it prints its status and stops
// on Ctrl+C.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"kidpcmonitor/agent"
	"kidpcmonitor/monitor"
	"kidpcmonitor/state"
	"kidpcmonitor/winplatform"
)

// version is set by release builds (-ldflags "-X main.version=v1.2.3").
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	dataDir := agent.DataDir()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	logFile := filepath.Join(dataDir, "pc_control.log")
	level, levelName := agent.LogLevelFromEnv()
	logs, err := agent.OpenLogs(logFile, level)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer logs.Close()
	log := logs.Logger("kid_pc_monitor")

	exe, _ := os.Executable()
	user := agent.CurrentUser()
	log.Info(fmt.Sprintf("Agent process starting (pid=%d, user=%s, script=%s, version=%s)",
		os.Getpid(), user, exe, version))

	controlLog := logs.Logger("PCTimeControl")
	platform := &winplatform.Platform{Logger: controlLog}

	control, err := monitor.New(monitor.Config{
		Platform:       platform,
		CurrentUser:    user,
		DataDir:        dataDir,
		ProgramDataDir: state.PlatformProgramDataDir(),
		Logger:         controlLog,
		StateLogger:    logs.Logger("kid_pc_monitor.agent_state"),
	})
	if err != nil {
		log.Error("Agent failed to start: " + err.Error())
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		control.Run(ctx)
	}()

	// The diagnostics only log; Get-NetConnectionProfile can take its full
	// 15 s timeout in a standard user's session, so enforcement must not wait.
	go platform.LogConnectivityDiagnostics(log, winplatform.ConnectivityInfo{
		User: user, Executable: exe, LogFile: logFile, LogLevel: levelName,
	})

	client := &agent.ReverseClient{Control: control, DataDir: dataDir, Logger: logs.Logger("AgentReverseClient")}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		client.Run(ctx)
	}()
	logs.Logger("AgentReverseClient").Info("Agent reverse TCP client started")

	log.Info("Agent running (enforcement + reverse TCP). " +
		"Verbose command logging: set KID_PC_MONITOR_LOG_LEVEL=DEBUG")
	fmt.Println("Agent is running. Press Ctrl+C to stop.")

	<-ctx.Done()
	fmt.Println("\nShutting down agent...")
	<-clientDone
	<-monitorDone
	log.Info("Agent stopped")
	fmt.Println("Agent stopped.")
	return 0
}
