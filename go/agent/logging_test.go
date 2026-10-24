package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedLogs(t *testing.T, level slog.Level, maxBytes int64) (*Logs, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pc_control.log")
	f, err := OpenRotatingFile(path, maxBytes, LogBackupCount)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	now := time.Date(2026, 10, 24, 15, 4, 5, 0, time.Local)
	return &Logs{out: f, level: level, now: func() time.Time { return now }}, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLogLineFormat(t *testing.T) {
	logs, path := fixedLogs(t, LevelInfo, LogMaxBytes)
	logs.Logger("AgentReverseClient").Warn("Reverse connect failed (refused); rediscovering")
	logs.Logger("kid_pc_monitor").Info("hello")
	logs.Logger("PCTimeControl").Debug("hidden at INFO")
	logs.Logger("kid_pc_monitor.agent_state").Warn("ignoring file", "path", `C:\a b\x.json`, "n", 3)
	logs.Logger("x").Log(nil, LevelCritical, "boom")
	want := "[2026-10-24 15:04:05] WARNING AgentReverseClient: Reverse connect failed (refused); rediscovering\n" +
		"[2026-10-24 15:04:05] INFO kid_pc_monitor: hello\n" +
		"[2026-10-24 15:04:05] WARNING kid_pc_monitor.agent_state: ignoring file path=\"C:\\\\a b\\\\x.json\" n=3\n" +
		"[2026-10-24 15:04:05] CRITICAL x: boom\n"
	if got := readFile(t, path); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestLogLevelFromEnv(t *testing.T) {
	for raw, want := range map[string]string{
		"": "INFO", "debug": "DEBUG", " Warning ": "WARNING", "WARN": "WARNING",
		"error": "ERROR", "fatal": "CRITICAL", "CRITICAL": "CRITICAL", "NOTSET": "NOTSET", "bogus": "INFO",
	} {
		t.Setenv("KID_PC_MONITOR_LOG_LEVEL", raw)
		if _, name := LogLevelFromEnv(); name != want {
			t.Errorf("%q: got %s, want %s", raw, name, want)
		}
	}
	t.Setenv("KID_PC_MONITOR_LOG_LEVEL", "NOTSET")
	if level, _ := LogLevelFromEnv(); level > LevelDebug {
		t.Error("NOTSET must let debug through")
	}
}

func TestRotation(t *testing.T) {
	logs, path := fixedLogs(t, LevelInfo, 200)
	log := logs.Logger("n")
	// Each line is 50 bytes: "[2026-10-24 15:04:05] INFO n: " (30) + 19 + "\n".
	msg := strings.Repeat("m", 19)
	for i := 0; i < 3; i++ {
		log.Info(msg)
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Fatal("rolled over too early")
	}
	log.Info(msg) // 150 + 50 >= 200: roll over first, as Python does
	if got := len(readFile(t, path)); got != 50 {
		t.Fatalf("active file is %d bytes, want 50", got)
	}
	if got := len(readFile(t, path+".1")); got != 150 {
		t.Fatalf(".1 is %d bytes, want 150", got)
	}
	// Keep going until more than LogBackupCount rollovers have happened.
	for i := 0; i < 4*(LogBackupCount+2); i++ {
		log.Info(msg)
	}
	for i := 1; i <= LogBackupCount; i++ {
		if _, err := os.Stat(path + "." + string(rune('0'+i))); err != nil {
			t.Errorf("backup .%d missing", i)
		}
	}
	if _, err := os.Stat(path + "." + string(rune('0'+LogBackupCount+1))); err == nil {
		t.Errorf("more than %d backups kept", LogBackupCount)
	}
}

func TestRotatingFileAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRotatingFile(path, 1000, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("new\n"))
	f.Close()
	if got := readFile(t, path); got != "old\nnew\n" {
		t.Fatalf("got %q", got)
	}
}
