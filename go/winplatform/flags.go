package winplatform

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// WTSSessionInfoEx lock-state values (WTSINFOEX_LEVEL1_W.SessionFlags).
const (
	wtsSessionStateLock    uint32 = 0
	wtsSessionStateUnlock  uint32 = 1
	wtsSessionStateUnknown uint32 = 0xFFFFFFFF
)

// WTSINFOEXW layout: a DWORD Level, then the union, which holds LARGE_INTEGERs
// and so starts on an 8-byte boundary. WTSINFOEX_LEVEL1_W begins SessionId,
// SessionState, SessionFlags (one 4-byte field each); nothing after
// SessionFlags matters for lock detection. The layout is the same on 32- and
// 64-bit Windows.
const (
	wtsInfoExSessionFlagsOffset = 16
	wtsInfoExMinSize            = wtsInfoExSessionFlagsOffset + 4
)

// sessionFlagsIndicateLocked interprets a SessionFlags value. known is false
// for WTS_SESSIONSTATE_UNKNOWN or any unexpected value, so the caller can fall
// back to another signal. inverted selects the Windows 7 / Server 2008 R2
// behavior, where LOCK and UNLOCK are swapped.
func sessionFlagsIndicateLocked(flags uint32, inverted bool) (locked, known bool) {
	switch flags {
	case wtsSessionStateLock:
		return !inverted, true
	case wtsSessionStateUnlock:
		return inverted, true
	default:
		return false, false
	}
}

// sessionFlagsInverted reports whether this Windows version has the swapped
// lock flags (NT 6.1: Windows 7 / Server 2008 R2).
func sessionFlagsInverted(major, minor uint32) bool {
	return major == 6 && minor == 1
}

// parseWTSInfoEx returns SessionFlags from a WTSINFOEXW buffer; ok is false
// when the buffer is too short to hold it.
func parseWTSInfoEx(buf []byte) (flags uint32, ok bool) {
	if len(buf) < wtsInfoExMinSize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf[wtsInfoExSessionFlagsOffset:]), true
}

// shutdownArgs are shutdown.exe's arguments for a shutdown in seconds, with
// the same comment the Python agent passes.
func shutdownArgs(seconds int64) []string {
	s := strconv.FormatInt(seconds, 10)
	return []string{"/s", "/t", s, "/c", "Computer will shutdown in " + s + " seconds"}
}

// messageText makes s safe to pass as a Win32 string.
func messageText(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
