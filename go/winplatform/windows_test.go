//go:build windows

package winplatform

import (
	"os"
	"path/filepath"
	"testing"
)

// Read-only checks against the real host. They never lock, shut down or pop
// up anything; use cmd/wincheck for those.

func TestSystemDir(t *testing.T) {
	if systemDir == "" {
		t.Fatal("GetSystemDirectoryW failed")
	}
	if _, err := os.Stat(filepath.Join(systemDir, "shutdown.exe")); err != nil {
		t.Fatalf("shutdown.exe not in %s: %v", systemDir, err)
	}
}

func TestOSVersion(t *testing.T) {
	major, minor, build, err := osVersion()
	if err != nil {
		t.Fatal(err)
	}
	if major < 6 {
		t.Fatalf("implausible version %d.%d.%d", major, minor, build)
	}
}

func TestHostnameMatchesOS(t *testing.T) {
	want, err := os.Hostname()
	if err != nil {
		t.Skip(err)
	}
	if got := (&Platform{}).Hostname(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCurrentSessionID(t *testing.T) {
	if _, err := currentSessionID(); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSessionState(t *testing.T) {
	p := &Platform{}
	d := p.Diagnose()
	t.Logf("%+v", d)
	if d.LogonUIErr != nil {
		t.Errorf("process snapshot: %v", d.LogonUIErr)
	}
	locked, err := p.CheckSessionLocked()
	if err != nil {
		t.Fatalf("CheckSessionLocked: %v", err)
	}
	active, err := p.SessionIsActive()
	if err != nil {
		t.Fatalf("SessionIsActive: %v", err)
	}
	t.Logf("locked=%v active=%v", locked, active)
	if locked && active {
		t.Error("session reported both locked and active")
	}
}
