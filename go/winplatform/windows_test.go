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

func TestParseProfiles(t *testing.T) {
	one, err := parseProfiles([]byte(`{"InterfaceAlias":"Wi-Fi","IPv4Connectivity":4,"NetworkCategory":1}` + "\r\n"))
	if err != nil || len(one) != 1 {
		t.Fatalf("one: %v %v", one, err)
	}
	if got := field(one[0], "InterfaceAlias") + " " + field(one[0], "IPv4Connectivity") + " " + field(one[0], "Missing"); got != "Wi-Fi 4 ?" {
		t.Errorf("fields = %q", got)
	}
	many, err := parseProfiles([]byte(`[{"InterfaceAlias":"a","NetworkCategory":null},{"InterfaceAlias":"b"}]`))
	if err != nil || len(many) != 2 || field(many[0], "NetworkCategory") != "None" {
		t.Fatalf("many: %v %v", many, err)
	}
	if none, err := parseProfiles([]byte("  \r\n")); none != nil || err != nil {
		t.Fatalf("empty: %v %v", none, err)
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
