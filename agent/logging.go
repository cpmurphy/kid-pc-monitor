package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Log rotation limits, as pc_control.py configures RotatingFileHandler.
const (
	LogMaxBytes    = 200_000
	LogBackupCount = 4
)

// Python logging level numbers mapped onto slog. Python's CRITICAL has no
// slog name, so it gets its own level.
const (
	LevelDebug    = slog.LevelDebug
	LevelInfo     = slog.LevelInfo
	LevelWarning  = slog.LevelWarn
	LevelError    = slog.LevelError
	LevelCritical = slog.Level(12)
	levelNotSet   = slog.Level(-100)
)

// LogLevelFromEnv reads KID_PC_MONITOR_LOG_LEVEL the way pc_control.py does
// (case-insensitive Python level names, INFO otherwise) and returns the
// level with its Python name.
func LogLevelFromEnv() (slog.Level, string) {
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("KID_PC_MONITOR_LOG_LEVEL"))) {
	case "DEBUG":
		return LevelDebug, "DEBUG"
	case "WARNING", "WARN":
		return LevelWarning, "WARNING"
	case "ERROR":
		return LevelError, "ERROR"
	case "CRITICAL", "FATAL":
		return LevelCritical, "CRITICAL"
	case "NOTSET":
		return levelNotSet, "NOTSET"
	default:
		return LevelInfo, "INFO"
	}
}

func levelName(l slog.Level) string {
	switch {
	case l >= LevelCritical:
		return "CRITICAL"
	case l >= LevelError:
		return "ERROR"
	case l >= LevelWarning:
		return "WARNING"
	case l >= LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// RotatingFile is an append-only log file that rolls over by size like
// Python's RotatingFileHandler: before a write that would reach maxBytes the
// file becomes <path>.1, older backups shift up, and <path>.<backups> is
// dropped. If a rename fails (another process has the file open without
// delete sharing) writing continues in the current file and the rollover is
// retried on the next write. Safe for concurrent use.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	f        *os.File
	size     int64
}

// OpenRotatingFile opens (or creates) path for appending.
func OpenRotatingFile(path string, maxBytes int64, backups int) (*RotatingFile, error) {
	r := &RotatingFile{path: path, maxBytes: maxBytes, backups: backups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, info.Size()
	return nil
}

// Write appends p, rolling over first when p would take the file to
// maxBytes. Callers write whole lines, so a line is never split across files.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.maxBytes > 0 && r.backups > 0 && r.size > 0 && r.size+int64(len(p)) >= r.maxBytes {
		r.rollover()
		if r.f == nil {
			if err := r.open(); err != nil {
				return 0, err
			}
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rollover() {
	r.f.Close()
	r.f = nil
	for i := r.backups - 1; i >= 1; i-- {
		src := r.path + "." + strconv.Itoa(i)
		if _, err := os.Stat(src); err == nil {
			_ = os.Remove(r.path + "." + strconv.Itoa(i+1))
			_ = os.Rename(src, r.path+"."+strconv.Itoa(i+1))
		}
	}
	first := r.path + ".1"
	_ = os.Remove(first)
	if err := os.Rename(r.path, first); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "log rollover failed: %v\n", err)
	}
	_ = r.open()
}

// Close closes the file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Logs writes Python-format log lines to one file:
//
//	[2026-10-24 15:04:05] WARNING AgentReverseClient: message
//
// Each logger carries the Python logger name its messages come from, so the
// web panel's Agent log page reads the same either way.
type Logs struct {
	out   *RotatingFile
	level slog.Level
	now   func() time.Time
}

// OpenLogs opens path with the agent's rotation limits.
func OpenLogs(path string, level slog.Level) (*Logs, error) {
	f, err := OpenRotatingFile(path, LogMaxBytes, LogBackupCount)
	if err != nil {
		return nil, err
	}
	return &Logs{out: f, level: level, now: time.Now}, nil
}

// Logger returns a logger that writes under the given logger name.
func (l *Logs) Logger(name string) *slog.Logger {
	return slog.New(&pyHandler{logs: l, name: name})
}

// Close closes the log file.
func (l *Logs) Close() error { return l.out.Close() }

type pyHandler struct {
	logs   *Logs
	name   string
	prefix string // group prefix for attribute keys
	attrs  string // pre-rendered " key=value" pairs
}

func (h *pyHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.logs.level }

func (h *pyHandler) Handle(_ context.Context, rec slog.Record) error {
	var b strings.Builder
	b.WriteByte('[')
	b.WriteString(h.logs.now().Format("2006-01-02 15:04:05"))
	b.WriteString("] ")
	b.WriteString(levelName(rec.Level))
	b.WriteByte(' ')
	b.WriteString(h.name)
	b.WriteString(": ")
	b.WriteString(rec.Message)
	b.WriteString(h.attrs)
	rec.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, h.prefix, a)
		return true
	})
	b.WriteByte('\n')
	_, err := h.logs.out.Write([]byte(b.String()))
	return err
}

func (h *pyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var b strings.Builder
	for _, a := range attrs {
		writeAttr(&b, h.prefix, a)
	}
	c := *h
	c.attrs += b.String()
	return &c
}

func (h *pyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.prefix += name + "."
	return &c
}

func writeAttr(b *strings.Builder, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			writeAttr(b, prefix+a.Key+".", g)
		}
		return
	}
	v := a.Value.String()
	if v == "" || strings.ContainsAny(v, " \t\n\"=") {
		v = strconv.Quote(v)
	}
	b.WriteByte(' ')
	b.WriteString(prefix + a.Key)
	b.WriteByte('=')
	b.WriteString(v)
}
