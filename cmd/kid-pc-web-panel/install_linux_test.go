package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Real tools the installer needs. Everything else on PATH is a fake.
var realTools = []string{
	"bash", "sh", "env", "dirname", "uname", "mkdir", "seq", "grep", "sleep", "id",
	"cat", "rm", "chmod", "cp", "mv", "mktemp", "awk", "sed", "head", "sha256sum",
}

func scriptPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "scripts", "install_web_panel_linux.sh")
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

type sandbox struct {
	t      *testing.T
	root   string
	bin    string
	home   string
	log    string
	goBin  string
	script string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	root := t.TempDir()
	s := &sandbox{
		t:      t,
		root:   root,
		bin:    filepath.Join(root, "bin"),
		home:   filepath.Join(root, "home"),
		log:    filepath.Join(root, "calls.log"),
		script: scriptPath(t),
	}
	s.goBin = filepath.Join(s.home, ".local", "share", "kid-pc-monitor", "bin", "kid-pc-web-panel")
	if err := os.MkdirAll(s.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(s.home, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range realTools {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("missing %s: %v", tool, err)
		}
		if err := os.Symlink(real, filepath.Join(s.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	s.fake("systemctl", "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >> \""+s.log+"\"\nexit 0\n")
	s.fake("loginctl", "#!/bin/sh\necho yes\n")
	s.fake("ss", "#!/bin/sh\necho 'LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*'\n")
	s.fake("uname", "#!/bin/sh\ncase \"$1\" in -m) echo x86_64 ;; *) echo Linux ;; esac\n")
	return s
}

func (s *sandbox) fake(name, body string) {
	s.t.Helper()
	path := filepath.Join(s.bin, name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.t.Fatal(err)
	}
	writeExecutable(s.t, path, body)
}

func (s *sandbox) runInstall(args ...string) (int, string, string) {
	s.t.Helper()
	argv := []string{
		filepath.Join(s.bin, "bash"), "-c",
		`source "$1"; REPO_ROOT="$2"; SRC_DIR="$2/src"; UNIT_DIR="$2/unit"; UNIT_PATH="$UNIT_DIR/$UNIT_NAME"; cmd_install "${@:3}"`,
		"bash", s.script, s.root,
	}
	argv = append(argv, args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{
		"PATH=" + s.bin,
		"HOME=" + s.home,
		"USER=parent",
	}
	cmd.Stdin = nil
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			s.t.Fatal(err)
		}
	}
	return code, stdout.String(), stderr.String()
}

func (s *sandbox) unitText() string {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(s.root, "unit", "kid-pc-monitor-web-panel.service"))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(b)
}

func (s *sandbox) calls() string {
	b, err := os.ReadFile(s.log)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		s.t.Fatal(err)
	}
	return string(b)
}

func (s *sandbox) binary(secretStatus int) string {
	s.t.Helper()
	path := filepath.Join(s.root, "built-panel")
	body := "#!/bin/sh\n" +
		"printf 'panel %s\\n' \"$*\" >> \"" + s.log + "\"\n" +
		"case \"$1\" in\n" +
		"    version) echo v9.9.9 ;;\n" +
		"    set-secret) exit " + itoa(secretStatus) + " ;;\n" +
		"    check-firewall) echo 'Firewall: checked' ;;\n" +
		"esac\nexit 0\n"
	writeExecutable(s.t, path, body)
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func (s *sandbox) release(corrupt bool) {
	s.t.Helper()
	dir := filepath.Join(s.root, "release")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.t.Fatal(err)
	}
	asset := filepath.Join(dir, "kid-pc-web-panel-linux-amd64")
	writeExecutable(s.t, asset, "#!/bin/sh\n"+
		"printf 'panel %s\\n' \"$*\" >> \""+s.log+"\"\n"+
		"case \"$1\" in\n"+
		"    version) echo v9.9.9 ;;\n"+
		"    set-secret) exit 0 ;;\n"+
		"    check-firewall) echo 'Firewall: checked' ;;\n"+
		"esac\nexit 0\n")
	sum, err := os.ReadFile(asset)
	if err != nil {
		s.t.Fatal(err)
	}
	digest := sha256.Sum256(sum)
	if corrupt {
		f, err := os.OpenFile(asset, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			s.t.Fatal(err)
		}
		if _, err := f.WriteString("# tampered\n"); err != nil {
			s.t.Fatal(err)
		}
		f.Close()
	}
	sums := strings.Repeat("0", 64) + "  kid-pc-agent-windows-amd64.exe\n" +
		hex.EncodeToString(digest[:]) + "  kid-pc-web-panel-linux-amd64\n"
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "latest.json"), []byte(`{"tag_name": "v9.9.9", "name": "x"}`), 0o644); err != nil {
		s.t.Fatal(err)
	}
	s.fake("curl", "#!/bin/sh\n"+
		"out=\"\"; url=\"\"\n"+
		"while [ $# -gt 0 ]; do\n"+
		"    case \"$1\" in -o) out=\"$2\"; shift ;; -*) ;; *) url=\"$1\" ;; esac\n"+
		"    shift\n"+
		"done\n"+
		"printf 'curl %s\\n' \"$url\" >> \""+s.log+"\"\n"+
		"case \"$url\" in\n"+
		"    */repos/cpmurphy/kid-pc-monitor/releases/latest) cp \""+dir+"/latest.json\" \"$out\" ;;\n"+
		"    */cpmurphy/kid-pc-monitor/releases/download/v9.9.9/*) cp \""+dir+"/${url##*/}\" \"$out\" ;;\n"+
		"    *) exit 22 ;;\n"+
		"esac\n")
}

func TestInstallsGivenBinary(t *testing.T) {
	s := newSandbox(t)
	code, stdout, stderr := s.runInstall("--binary", s.binary(0))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	st, err := os.Stat(s.goBin)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&0o111 == 0 {
		t.Fatalf("installed binary is not executable: %v", st.Mode())
	}
	unit := s.unitText()
	if !strings.Contains(unit, "ExecStart="+s.goBin+" serve") {
		t.Fatalf("unit %s", unit)
	}
	if strings.Contains(unit, "PYTHONPATH") {
		t.Fatalf("unit still mentions PYTHONPATH: %s", unit)
	}
	calls := s.calls()
	if !strings.Contains(calls, "panel set-secret") {
		t.Fatalf("calls %s", calls)
	}
	if !strings.Contains(calls, "panel check-firewall --interactive 5000 9998") {
		t.Fatalf("calls %s", calls)
	}
	if !strings.Contains(calls, "systemctl --user restart kid-pc-monitor-web-panel.service") {
		t.Fatalf("calls %s", calls)
	}
	if !strings.Contains(stdout, "Installed:") || !strings.Contains(stdout, "v9.9.9") {
		t.Fatalf("stdout %s", stdout)
	}
	if !strings.Contains(stdout, "Firewall: checked") {
		t.Fatalf("stdout %s", stdout)
	}
	if !strings.Contains(stdout, "lingering is on") {
		t.Fatalf("stdout %s", stdout)
	}
}

func TestGoFlagIsAnAlias(t *testing.T) {
	s := newSandbox(t)
	code, stdout, stderr := s.runInstall("--go", "--binary", s.binary(0))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(s.goBin); err != nil {
		t.Fatal(err)
	}
}

func TestMissingBinaryStopsBeforeTheUnit(t *testing.T) {
	s := newSandbox(t)
	code, _, stderr := s.runInstall("--binary", filepath.Join(s.root, "nope"))
	if code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr, "Panel binary not found") {
		t.Fatalf("stderr %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(s.root, "unit", "kid-pc-monitor-web-panel.service")); !os.IsNotExist(err) {
		t.Fatal("unit should not exist")
	}
	if _, err := os.Stat(s.goBin); !os.IsNotExist(err) {
		t.Fatal("binary should not exist")
	}
}

func TestDownloadsReleaseAndChecksSHA256(t *testing.T) {
	s := newSandbox(t)
	s.release(false)
	code, stdout, stderr := s.runInstall()
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "SHA-256 verified") {
		t.Fatalf("stdout %s", stdout)
	}
	if !strings.Contains(s.calls(), "releases/download/v9.9.9/kid-pc-web-panel-linux-amd64") {
		t.Fatalf("calls %s", s.calls())
	}
	if _, err := os.Stat(s.goBin); err != nil {
		t.Fatal(err)
	}
}

func TestVersionWithoutGoFlagDownloadsThatRelease(t *testing.T) {
	s := newSandbox(t)
	s.release(false)
	code, stdout, stderr := s.runInstall("--version", "v9.9.9")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(s.calls(), "releases/download/v9.9.9/kid-pc-web-panel-linux-amd64") {
		t.Fatalf("calls %s", s.calls())
	}
}

func TestDownloadWithBadChecksumKeepsOldBinary(t *testing.T) {
	s := newSandbox(t)
	if err := os.MkdirAll(filepath.Dir(s.goBin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.goBin, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.release(true)
	code, _, stderr := s.runInstall("--version", "v9.9.9")
	if code == 0 {
		t.Fatal("expected failure")
	}
	if !strings.Contains(stderr, "does not match SHA256SUMS") {
		t.Fatalf("stderr %s", stderr)
	}
	got, err := os.ReadFile(s.goBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("binary %q", got)
	}
	if _, err := os.Stat(filepath.Join(s.root, "unit", "kid-pc-monitor-web-panel.service")); !os.IsNotExist(err) {
		t.Fatal("unit should not exist")
	}
	entries, err := os.ReadDir(filepath.Dir(s.goBin))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "kid-pc-web-panel" {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestCopiesLegacyAuthFileOnce(t *testing.T) {
	s := newSandbox(t)
	legacy := filepath.Join(s.root, "src", "kid_pc_monitor", "web_panel_auth.json")
	writeExecutable(s.t, legacy, "{\"password_hash\": \"legacy\"}")
	if err := os.Chmod(legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(s.home, ".config", "kid-pc-monitor", "web_panel_auth.json")
	code, stdout, stderr := s.runInstall("--binary", s.binary(0))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	got, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"password_hash\": \"legacy\"}" {
		t.Fatalf("canonical %s", got)
	}
	st, err := os.Stat(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if err := os.WriteFile(canonical, []byte("{\"password_hash\": \"newer\"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = s.runInstall("--binary", s.binary(0))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	got, err = os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"password_hash\": \"newer\"}" {
		t.Fatalf("canonical overwritten: %s", got)
	}
}

func TestCancelledSecretDoesNotStopTheInstall(t *testing.T) {
	s := newSandbox(t)
	code, stdout, stderr := s.runInstall("--binary", s.binary(1))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "Set it later with:") {
		t.Fatalf("stdout %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(s.root, "unit", "kid-pc-monitor-web-panel.service")); err != nil {
		t.Fatal(err)
	}
}

func TestOffersLingerOnlyWhenDisabled(t *testing.T) {
	s := newSandbox(t)
	s.fake("loginctl", "#!/bin/sh\necho no\n")
	code, stdout, stderr := s.runInstall("--binary", s.binary(0))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "sudo loginctl enable-linger parent") {
		t.Fatalf("stdout %s", stdout)
	}
}
