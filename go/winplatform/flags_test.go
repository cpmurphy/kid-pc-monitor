package winplatform

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// Mirrors tests/test_windows_lock_detection.py.
func TestSessionFlagsIndicateLocked(t *testing.T) {
	cases := []struct {
		name     string
		flags    uint32
		inverted bool
		locked   bool
		known    bool
	}{
		{"lock means locked", wtsSessionStateLock, false, true, true},
		{"unlock means unlocked", wtsSessionStateUnlock, false, false, true},
		{"unknown", wtsSessionStateUnknown, false, false, false},
		{"inverted lock means unlocked", wtsSessionStateLock, true, false, true},
		{"inverted unlock means locked", wtsSessionStateUnlock, true, true, true},
		{"unexpected value", 42, false, false, false},
		{"unexpected value inverted", 42, true, false, false},
	}
	for _, tc := range cases {
		locked, known := sessionFlagsIndicateLocked(tc.flags, tc.inverted)
		if locked != tc.locked || known != tc.known {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, locked, known, tc.locked, tc.known)
		}
	}
}

func TestSessionFlagsInverted(t *testing.T) {
	for _, v := range []struct {
		major, minor uint32
		want         bool
	}{{6, 1, true}, {6, 0, false}, {6, 2, false}, {6, 3, false}, {10, 0, false}, {5, 1, false}} {
		if got := sessionFlagsInverted(v.major, v.minor); got != v.want {
			t.Errorf("%d.%d: got %v, want %v", v.major, v.minor, got, v.want)
		}
	}
}

func TestParseWTSInfoEx(t *testing.T) {
	buf := make([]byte, wtsInfoExMinSize)
	binary.LittleEndian.PutUint32(buf[0:], 1)  // Level
	binary.LittleEndian.PutUint32(buf[8:], 3)  // SessionId
	binary.LittleEndian.PutUint32(buf[12:], 0) // SessionState (WTSActive)
	binary.LittleEndian.PutUint32(buf[16:], wtsSessionStateUnlock)
	if flags, ok := parseWTSInfoEx(buf); !ok || flags != wtsSessionStateUnlock {
		t.Fatalf("got (%d, %v), want (%d, true)", flags, ok, wtsSessionStateUnlock)
	}
	if _, ok := parseWTSInfoEx(buf[:wtsInfoExMinSize-1]); ok {
		t.Fatal("short buffer accepted")
	}
	if _, ok := parseWTSInfoEx(nil); ok {
		t.Fatal("nil buffer accepted")
	}
}

func TestShutdownArgs(t *testing.T) {
	want := []string{"/s", "/t", "60", "/c", "Computer will shutdown in 60 seconds"}
	if got := shutdownArgs(60); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMessageText(t *testing.T) {
	if got := messageText("a\x00b"); got != "ab" {
		t.Fatalf("got %q", got)
	}
}
