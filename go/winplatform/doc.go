// Package winplatform is the Windows implementation of monitor.Platform, a
// port of src/kid_pc_monitor/platforms/windows.py. Standard library only: the
// Win32 calls go through syscall.NewLazyDLL.
//
//   - CheckSessionLocked asks WTSQuerySessionInformationW(WTSSessionInfoEx) for
//     this session's lock flag (correct even after the lock screen's display
//     sleeps and LogonUI.exe exits) and falls back to looking for LogonUI.exe
//     in this session when that query fails or reports an unknown state. On
//     Windows 7 / Server 2008 R2 the documented lock/unlock values are swapped;
//     the OS version comes from RtlGetVersion, which is not manifest-shimmed.
//   - SessionIsActive is true when this process's session is the active console
//     session and is not locked.
//   - LockWorkstation calls user32!LockWorkStation.
//   - Shutdown / CancelShutdown run shutdown.exe /s /t N /c ... and /a without a
//     console window.
//   - ShowMessage shows a topmost warning box on its own goroutine and returns
//     at once; the box closes itself after 60 s (MessageBoxTimeoutW, falling
//     back to a plain MessageBoxW).
//
// The flag interpretation, WTSINFOEX parsing and shutdown arguments live in
// files without a build tag so they are tested on every platform.
//
// # Differences from the Python platform
//
//   - Failures are returned instead of swallowed, so monitor.Control logs them
//     once and keeps enforcing: a LockWorkStation that fails (for example from
//     a process with no interactive desktop) leaves the monitor's "locked" flag
//     unset, and a failing shutdown.exe is reported rather than logged as done.
//     Where Python's fallback returned False for an unknown lock state, Go
//     returns an error, which the monitor also treats as unlocked.
//   - Popups use a native message box instead of tkinter. NUL characters in
//     the text are dropped (Win32 strings cannot carry them).
//   - log_connectivity_diagnostics is not part of monitor.Platform and is not
//     ported here; it belongs with the agent's main.
package winplatform
