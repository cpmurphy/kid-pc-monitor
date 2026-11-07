package firewall

import (
	"strconv"
	"strings"
	"testing"
)

var ports = []int{5000, 9998}

func runner(responses map[string][2]any) Runner {
	return func(cmd []string) (int, string) {
		key := strings.Join(cmd, "\x00")
		if resp, ok := responses[key]; ok {
			return resp[0].(int), resp[1].(string)
		}
		return 127, ""
	}
}

func cmd(parts ...string) string { return strings.Join(parts, "\x00") }

func reader(files map[string]string) Reader {
	return func(path string) (string, bool) {
		text, ok := files[path]
		return text, ok
	}
}

func ufwEnabled() map[string]string {
	return map[string]string{ufwConf: "ENABLED=yes\nLOGLEVEL=low\n"}
}

func ufwDenyDefault() map[string]string {
	return map[string]string{ufwDefaults: "DEFAULT_INPUT_POLICY=\"DROP\"\n"}
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func iface(name string) *string { return &name }

func TestNothingInstalled(t *testing.T) {
	report := Check(ports, runner(nil), reader(nil), iface("eth0"))
	if report.Status != "none" {
		t.Fatalf("status %q", report.Status)
	}
	if !strings.Contains(Format(report, ports), "no changes needed") {
		t.Fatalf("report %q", Format(report, ports))
	}
}

func TestUfwInstalledButDisabled(t *testing.T) {
	// The ufw systemd unit reports "active" even when ufw itself is disabled.
	run := runner(map[string][2]any{
		cmd("systemctl", "is-active", "ufw.service"): {0, "active\n"},
	})
	read := reader(map[string]string{ufwConf: "ENABLED=no\n"})
	if got := Check(ports, run, read, iface("eth0")).Status; got != "none" {
		t.Fatalf("status %q", got)
	}
}

func TestFirewalldInstalledButStopped(t *testing.T) {
	run := runner(map[string][2]any{
		cmd("firewall-cmd", "--state"): {252, "not running\n"},
	})
	if got := Check(ports, run, reader(nil), iface("eth0")).Status; got != "none" {
		t.Fatalf("status %q", got)
	}
}

func TestUfwRulesAllowBothPorts(t *testing.T) {
	rules := "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 in\n" +
		"-A ufw-user-input -p tcp --dport 5000 -j ACCEPT\n" +
		"### tuple ### allow any 9998 0.0.0.0/0 any 0.0.0.0/0 in\n"
	read := reader(merge(ufwEnabled(), ufwDenyDefault(), map[string]string{ufwUserRules: rules}))
	report := Check(ports, runner(nil), read, iface("eth0"))
	if report.Status != "open" || report.Firewall != "ufw" {
		t.Fatalf("%+v", report)
	}
}

func TestUfwRulesMissingOnePort(t *testing.T) {
	rules := "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 in\n"
	read := reader(merge(ufwEnabled(), ufwDenyDefault(), map[string]string{ufwUserRules: rules}))
	report := Check(ports, runner(nil), read, iface("eth0"))
	if report.Status != "blocked" {
		t.Fatalf("status %q", report.Status)
	}
	if len(report.BlockedPorts) != 1 || report.BlockedPorts[0] != 9998 {
		t.Fatalf("blocked %v", report.BlockedPorts)
	}
	want := []string{"sudo", "ufw", "allow", "9998/tcp"}
	if len(report.Commands) != 1 || strings.Join(report.Commands[0], " ") != strings.Join(want, " ") {
		t.Fatalf("commands %v", report.Commands)
	}
}

func TestUfwLanSubnetAllowsEveryPort(t *testing.T) {
	rules := "### tuple ### allow any any 0.0.0.0/0 any 192.168.1.0/24 in\n"
	read := reader(merge(ufwEnabled(), ufwDenyDefault(), map[string]string{ufwUserRules: rules}))
	if got := Check(ports, runner(nil), read, iface("eth0")).Status; got != "open" {
		t.Fatalf("status %q", got)
	}
}

func TestUfwOutboundAndUDPDoNotCount(t *testing.T) {
	rules := "### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 out\n" +
		"### tuple ### allow udp 9998 0.0.0.0/0 any 0.0.0.0/0 in\n"
	read := reader(merge(ufwEnabled(), ufwDenyDefault(), map[string]string{ufwUserRules: rules}))
	report := Check(ports, runner(nil), read, iface("eth0"))
	if strings.Join(ints(report.BlockedPorts), ",") != "5000,9998" {
		t.Fatalf("blocked %v", report.BlockedPorts)
	}
}

func TestUfwPortRange(t *testing.T) {
	rules := "### tuple ### allow tcp 4000:10000 0.0.0.0/0 any 0.0.0.0/0 in\n"
	read := reader(merge(ufwEnabled(), ufwDenyDefault(), map[string]string{ufwUserRules: rules}))
	if got := Check(ports, runner(nil), read, iface("eth0")).Status; got != "open" {
		t.Fatalf("status %q", got)
	}
}

func TestUfwDefaultAcceptIsOpen(t *testing.T) {
	read := reader(merge(ufwEnabled(), map[string]string{ufwDefaults: "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n"}))
	if got := Check(ports, runner(nil), read, iface("eth0")).Status; got != "open" {
		t.Fatalf("status %q", got)
	}
}

func TestUfwUnreadableRulesFallBackToCachedSudo(t *testing.T) {
	statusOut := "Status: active\n\n" +
		"To                         Action      From\n" +
		"--                         ------      ----\n" +
		"5000/tcp                   ALLOW       Anywhere\n" +
		"9998/tcp (v6)              ALLOW       Anywhere (v6)\n"
	run := runner(map[string][2]any{
		cmd("sudo", "-n", "ufw", "status"): {0, statusOut},
	})
	read := reader(merge(ufwEnabled(), ufwDenyDefault()))
	if got := Check(ports, run, read, iface("eth0")).Status; got != "open" {
		t.Fatalf("status %q", got)
	}
}

func TestUfwUnreadableRulesWithoutSudoIsUnknown(t *testing.T) {
	run := runner(map[string][2]any{
		cmd("sudo", "-n", "ufw", "status"): {1, ""},
	})
	read := reader(merge(ufwEnabled(), ufwDenyDefault()))
	report := Check(ports, run, read, iface("eth0"))
	if report.Status != "unknown" || report.Firewall != "ufw" {
		t.Fatalf("%+v", report)
	}
	text := Format(report, ports)
	if !strings.Contains(text, "sudo ufw allow 5000/tcp") || !strings.Contains(text, "sudo ufw allow 9998/tcp") {
		t.Fatalf("report %q", text)
	}
	if !CanOffer(report) {
		t.Fatal("expected to offer a fix")
	}
}

func firewalldRun(portsOut string, listStatus int) Runner {
	return runner(map[string][2]any{
		cmd("firewall-cmd", "--state"):                      {0, "running\n"},
		cmd("firewall-cmd", "--get-zone-of-interface=eth0"): {0, "home\n"},
		cmd("firewall-cmd", "--zone=home", "--list-ports"):  {listStatus, portsOut},
	})
}

func TestFirewalldWorkstationRangeIsOpen(t *testing.T) {
	report := Check(ports, firewalldRun("1025-65535/tcp 1025-65535/udp\n", 0), reader(nil), iface("eth0"))
	if report.Status != "open" || report.Firewall != "firewalld" {
		t.Fatalf("%+v", report)
	}
}

func TestFirewalldBlockedPortsSuggestZoneCommands(t *testing.T) {
	report := Check(ports, firewalldRun("\n", 0), reader(nil), iface("eth0"))
	if report.Status != "blocked" {
		t.Fatalf("status %q", report.Status)
	}
	want0 := "sudo firewall-cmd --zone=home --permanent --add-port=5000/tcp --add-port=9998/tcp"
	if len(report.Commands) != 2 || strings.Join(report.Commands[0], " ") != want0 {
		t.Fatalf("commands %v", report.Commands)
	}
	if strings.Join(report.Commands[1], " ") != "sudo firewall-cmd --reload" {
		t.Fatalf("reload %v", report.Commands[1])
	}
}

func TestFirewalldFallsBackToDefaultZone(t *testing.T) {
	run := runner(map[string][2]any{
		cmd("firewall-cmd", "--state"):                       {0, "running\n"},
		cmd("firewall-cmd", "--get-default-zone"):            {0, "public\n"},
		cmd("firewall-cmd", "--zone=public", "--list-ports"): {0, "5000/tcp 9998/tcp\n"},
	})
	if got := Check(ports, run, reader(nil), nil).Status; got != "open" {
		t.Fatalf("status %q", got)
	}
}

func TestFirewalldPermissionDeniedIsUnknown(t *testing.T) {
	report := Check(ports, firewalldRun("", 11), reader(nil), iface("eth0"))
	if report.Status != "unknown" || report.Firewall != "firewalld" {
		t.Fatalf("%+v", report)
	}
	if CanOffer(report) {
		t.Fatal("firewalld unknown should not offer a fix")
	}
}

func TestActiveNftablesIsUnknown(t *testing.T) {
	run := runner(map[string][2]any{
		cmd("systemctl", "is-active", "nftables.service"): {0, "active\n"},
	})
	report := Check(ports, run, reader(nil), iface("eth0"))
	if report.Status != "unknown" || report.Firewall != "nftables" {
		t.Fatalf("%+v", report)
	}
	if CanOffer(report) {
		t.Fatal("nftables should not offer a fix")
	}
}

func ints(ns []int) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = strconv.Itoa(n)
	}
	return out
}
