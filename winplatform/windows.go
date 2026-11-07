//go:build windows

package winplatform

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"kidpcmonitor/monitor"
)

var _ monitor.Platform = (*Platform)(nil)

// kernel32 is a KnownDLL, so loading it by name is safe; the others are
// loaded from the system directory by absolute path, not the search path.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = systemDLL("user32.dll")
	wtsapi32 = systemDLL("wtsapi32.dll")
	ntdll    = systemDLL("ntdll.dll")

	procGetSystemDirectoryW          = kernel32.NewProc("GetSystemDirectoryW")
	procProcessIdToSessionId         = kernel32.NewProc("ProcessIdToSessionId")
	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procLockWorkStation              = user32.NewProc("LockWorkStation")
	procMessageBoxW                  = user32.NewProc("MessageBoxW")
	procMessageBoxTimeoutW           = user32.NewProc("MessageBoxTimeoutW") // undocumented, present since XP
	procWTSQuerySessionInformationW  = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory                = wtsapi32.NewProc("WTSFreeMemory")
	procRtlGetVersion                = ntdll.NewProc("RtlGetVersion")
)

const (
	wtsCurrentServerHandle = 0
	wtsCurrentSession      = 0xFFFFFFFF
	wtsSessionInfoEx       = 25 // WTS_INFO_CLASS WTSSessionInfoEx
	noSession              = 0xFFFFFFFF

	createNoWindow = 0x08000000

	mbOK            = 0x00000000
	mbIconWarning   = 0x00000030
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000

	messageTimeout  = 60 * time.Second
	shutdownTimeout = 15 * time.Second
)

// Platform implements monitor.Platform on Windows. The zero value is ready
// to use.
type Platform struct {
	// Logger receives debug notes about lock-detection fallbacks and popup
	// failures (which happen after ShowMessage has returned). Defaults to
	// slog.Default.
	Logger *slog.Logger
}

func (p *Platform) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

// CheckSessionLocked reports whether this session's workstation is locked.
//
// The WTS session flags are authoritative and stay correct after a locked
// screen's display sleeps (Windows ends LogonUI.exe then). LogonUI.exe in this
// session is only consulted when the WTS query fails or reports an unknown
// state; it is filtered by session so another user's locked session under fast
// user switching does not read as ours.
func (p *Platform) CheckSessionLocked() (bool, error) {
	flags, err := querySessionFlags()
	if err == nil {
		if locked, known := sessionFlagsIndicateLocked(flags, flagsInverted()); known {
			return locked, nil
		}
		p.logger().Debug(fmt.Sprintf("WTS lock state unknown (SessionFlags=%#x); checking LogonUI.exe", flags))
	} else {
		p.logger().Debug("WTS lock query failed: " + err.Error())
	}
	sid, sidErr := currentSessionID()
	locked, err := processInSession("LogonUI.exe", sid, sidErr != nil)
	if err != nil {
		return false, fmt.Errorf("checking lock state (LogonUI): %w", err)
	}
	return locked, nil
}

// SessionIsActive reports whether this session is the active console session
// and not locked. When the session ids cannot be read it falls back to the
// lock state alone.
func (p *Platform) SessionIsActive() (bool, error) {
	if our, err := currentSessionID(); err == nil && procWTSGetActiveConsoleSessionId.Find() == nil {
		r, _, _ := procWTSGetActiveConsoleSessionId.Call()
		if active := uint32(r); active == noSession || active != our {
			return false, nil
		}
	}
	locked, err := p.CheckSessionLocked()
	return !locked, err
}

// LockWorkstation locks the workstation. It fails when this process is not
// running on the interactive desktop.
func (p *Platform) LockWorkstation() error {
	if err := procLockWorkStation.Find(); err != nil {
		return err
	}
	if r, _, e := procLockWorkStation.Call(); r == 0 {
		return winError("LockWorkStation", e)
	}
	return nil
}

// Shutdown schedules a shutdown in seconds with a visible warning.
func (p *Platform) Shutdown(seconds int64) error {
	return runShutdown(shutdownArgs(seconds)...)
}

// CancelShutdown aborts a pending shutdown. shutdown.exe fails (exit 1116)
// when none is pending.
func (p *Platform) CancelShutdown() error {
	return runShutdown("/a")
}

// ShowMessage shows a topmost warning box and returns without waiting for
// it; the box closes itself after a minute.
func (p *Platform) ShowMessage(message, title string) error {
	text, err := syscall.UTF16PtrFromString(messageText(message))
	if err != nil {
		return err
	}
	caption, err := syscall.UTF16PtrFromString(messageText(title))
	if err != nil {
		return err
	}
	if err := procMessageBoxW.Find(); err != nil {
		return err
	}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		style := uintptr(mbOK | mbIconWarning | mbSetForeground | mbTopmost)
		var r uintptr
		var e error
		if procMessageBoxTimeoutW.Find() == nil {
			r, _, e = procMessageBoxTimeoutW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)),
				style, 0, uintptr(messageTimeout/time.Millisecond))
		} else {
			r, _, e = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), style)
		}
		if r == 0 {
			p.logger().Error("Error showing message: " + winError("MessageBox", e).Error())
		}
	}()
	return nil
}

// Hostname is the DNS host name, as Python's platform.node() returns it.
func (p *Platform) Hostname() string {
	if name, err := os.Hostname(); err == nil {
		return name
	}
	return os.Getenv("COMPUTERNAME")
}

// Diagnostics is a snapshot of the signals behind the lock and session state,
// for logging and manual checks.
type Diagnostics struct {
	OSVersion      string
	FlagsInverted  bool
	ProcessSession uint32
	ProcessErr     error
	ConsoleSession uint32 // 0xFFFFFFFF when no session is attached
	WTSFlags       uint32
	WTSErr         error
	LogonUI        bool // LogonUI.exe running in this session
	LogonUIErr     error
}

// Diagnose collects Diagnostics.
func (p *Platform) Diagnose() Diagnostics {
	var d Diagnostics
	major, minor, build, err := osVersion()
	if err != nil {
		d.OSVersion = err.Error()
	} else {
		d.OSVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}
	d.FlagsInverted = flagsInverted()
	d.ProcessSession, d.ProcessErr = currentSessionID()
	d.ConsoleSession = noSession
	if procWTSGetActiveConsoleSessionId.Find() == nil {
		r, _, _ := procWTSGetActiveConsoleSessionId.Call()
		d.ConsoleSession = uint32(r)
	}
	d.WTSFlags, d.WTSErr = querySessionFlags()
	d.LogonUI, d.LogonUIErr = processInSession("LogonUI.exe", d.ProcessSession, d.ProcessErr != nil)
	return d
}

// --- Win32 helpers ----------------------------------------------------------

// winError names a failed call; e is the error LazyProc.Call returned, which
// can be Errno(0) when the API did not set a last error.
func winError(name string, e error) error {
	var errno syscall.Errno
	if e == nil || (errors.As(e, &errno) && errno == 0) {
		return fmt.Errorf("%s failed", name)
	}
	return fmt.Errorf("%s: %w", name, e)
}

var systemDir = func() string {
	if procGetSystemDirectoryW.Find() != nil {
		return ""
	}
	buf := make([]uint16, syscall.MAX_PATH)
	r, _, _ := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 || int(r) >= len(buf) {
		return ""
	}
	return syscall.UTF16ToString(buf[:r])
}()

func systemDLL(name string) *syscall.LazyDLL {
	if systemDir == "" {
		return syscall.NewLazyDLL(name)
	}
	return syscall.NewLazyDLL(filepath.Join(systemDir, name))
}

func processSessionID(pid uint32) (uint32, error) {
	if err := procProcessIdToSessionId.Find(); err != nil {
		return 0, err
	}
	var sid uint32
	if r, _, e := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid))); r == 0 {
		return 0, winError("ProcessIdToSessionId", e)
	}
	return sid, nil
}

func currentSessionID() (uint32, error) {
	return processSessionID(uint32(os.Getpid()))
}

// querySessionFlags returns WTSINFOEX_LEVEL1_W.SessionFlags for this session.
func querySessionFlags() (uint32, error) {
	if err := procWTSQuerySessionInformationW.Find(); err != nil {
		return 0, err
	}
	if err := procWTSFreeMemory.Find(); err != nil {
		return 0, err
	}
	var buf *byte
	var n uint32
	r, _, e := procWTSQuerySessionInformationW.Call(wtsCurrentServerHandle, wtsCurrentSession, wtsSessionInfoEx,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return 0, winError("WTSQuerySessionInformationW", e)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	flags, ok := parseWTSInfoEx(unsafe.Slice(buf, n))
	if !ok {
		return 0, fmt.Errorf("WTSSessionInfoEx returned %d bytes", n)
	}
	return flags, nil
}

// processInSession reports whether image (case-insensitive) is running in
// session, or in any session when anySession is set.
func processInSession(image string, session uint32, anySession bool) (bool, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(snap)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = syscall.Process32First(snap, &entry); err == nil; err = syscall.Process32Next(snap, &entry) {
		if !strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), image) {
			continue
		}
		if anySession {
			return true, nil
		}
		if sid, sidErr := processSessionID(entry.ProcessID); sidErr == nil && sid == session {
			return true, nil
		}
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
		return false, fmt.Errorf("Process32: %w", err)
	}
	return false, nil
}

type osVersionInfo struct {
	size, major, minor, build, platformID uint32
	csdVersion                            [128]uint16
}

// osVersion is the real Windows version; RtlGetVersion is not subject to the
// compatibility shims that make GetVersionEx lie to unmanifested programs.
func osVersion() (major, minor, build uint32, err error) {
	if err := procRtlGetVersion.Find(); err != nil {
		return 0, 0, 0, err
	}
	var info osVersionInfo
	info.size = uint32(unsafe.Sizeof(info))
	if status, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&info))); status != 0 {
		return 0, 0, 0, fmt.Errorf("RtlGetVersion: NTSTATUS %#x", status)
	}
	return info.major, info.minor, info.build, nil
}

var flagsInverted = sync.OnceValue(func() bool {
	major, minor, _, err := osVersion()
	return err == nil && sessionFlagsInverted(major, minor)
})

func runShutdown(args ...string) error {
	exe := "shutdown.exe"
	if systemDir != "" {
		exe = filepath.Join(systemDir, exe)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if out, err := cmd.CombinedOutput(); err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("shutdown %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("shutdown %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
