// Package firewall decides whether a Linux host firewall will block the web
// panel's ports. The installer uses it so it only suggests changes when a
// firewall is actually active.
//
// Everything here runs without root: firewalld answers read-only queries over
// D-Bus, and ufw's enabled flag and default policy live in world-readable
// files. When the rules themselves cannot be read, the report says so instead
// of guessing.
//
// The behavior matches the checker the original Python panel used
// (linux_firewall.py), so the installer's advice stays the same.
package firewall

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ufwConf      = "/etc/ufw/ufw.conf"
	ufwDefaults  = "/etc/default/ufw"
	ufwUserRules = "/etc/ufw/user.rules"
	rtfUp        = 0x1
)

// Services that load raw nftables/iptables rules we cannot read without root.
var rawFirewallServices = []string{"nftables", "iptables", "netfilter-persistent"}

// Runner returns (exit status, stdout). Status 127 means the command is not installed.
type Runner func(cmd []string) (int, string)

// Reader returns the file's text. The bool is false when it is missing or unreadable.
type Reader func(path string) (string, bool)

// Report is the outcome of Check.
//
// Status is one of:
//
//   - "none" — no active firewall found; nothing to change.
//   - "open" — a firewall is active and already allows every port.
//   - "blocked" — a firewall is active and does not allow BlockedPorts.
//   - "unknown" — a firewall is active but its rules could not be read.
type Report struct {
	Status       string
	Firewall     string
	BlockedPorts []int
	Commands     [][]string
	Detail       string
}

// Check reports whether an active host firewall would block inbound TCP ports.
// Nil run/read use the real machine. A nil iface looks up the Linux default
// route; a non-nil iface (including "") is used as given.
func Check(ports []int, run Runner, read Reader, iface *string) Report {
	if run == nil {
		run = defaultRun
	}
	if read == nil {
		read = defaultRead
	}
	name := ""
	if iface != nil {
		name = *iface
	} else {
		name = linuxDefaultInterface()
	}
	portList := append([]int(nil), ports...)
	if report, ok := checkFirewalld(run, portList, name); ok {
		return report
	}
	if report, ok := checkUfw(run, read, portList); ok {
		return report
	}
	if report, ok := checkRawServices(run); ok {
		return report
	}
	return Report{Status: "none"}
}

// Format renders the report the installer prints.
func Format(report Report, ports []int) string {
	portText := portText(ports)
	detail := ""
	if report.Detail != "" && report.Status == "open" {
		detail = " (" + report.Detail + ")"
	}
	switch report.Status {
	case "none":
		return "Firewall: no active firewall found (checked firewalld, ufw, nftables/iptables);\n" +
			"  no changes needed for " + portText + "."
	case "open":
		return fmt.Sprintf("Firewall: %s already allows %s%s.", report.Firewall, portText, detail)
	}
	var lines []string
	if report.Status == "blocked" {
		lines = append(lines, fmt.Sprintf("Firewall: %s is active and blocks %s.", report.Firewall, portTextOf(report.BlockedPorts)))
		lines = append(lines, "  Kid PCs and your phone cannot reach the panel until these are allowed:")
	} else {
		lines = append(lines, "Firewall: "+report.Detail)
		if report.Firewall == "ufw" {
			lines = append(lines, "  If you have not already allowed "+portText+", run:")
		} else {
			lines = append(lines, "  Check that it allows inbound "+portText+", e.g.:")
		}
	}
	for _, cmd := range report.Commands {
		lines = append(lines, "    "+strings.Join(cmd, " "))
	}
	return strings.Join(lines, "\n")
}

// CanOffer reports whether the installer may offer to run the suggested commands.
// Only ufw and firewalld changes are offered; ufw allow is safe to repeat.
func CanOffer(report Report) bool {
	if report.Status == "blocked" {
		return report.Firewall == "ufw" || report.Firewall == "firewalld"
	}
	return report.Status == "unknown" && report.Firewall == "ufw"
}

// Offer asks on stdin and runs the suggested commands. EOF or any answer other
// than y/yes leaves the firewall unchanged. A failed command returns an error
// after printing the same line the original checker printed.
func Offer(report Report, in io.Reader, out, errOut io.Writer) error {
	if !CanOffer(report) {
		return nil
	}
	fmt.Fprint(out, "  Run these now with sudo? [y/N]: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer != "y" && answer != "yes" {
		return nil
	}
	for _, cmd := range report.Commands {
		c := exec.Command(cmd[0], cmd[1:]...)
		c.Stdin = in
		c.Stdout = out
		c.Stderr = errOut
		runErr := c.Run()
		if runErr == nil {
			continue
		}
		code := 1
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code = ee.ExitCode()
		}
		fmt.Fprintf(errOut, "  Command failed (%d): %s\n", code, strings.Join(cmd, " "))
		return fmt.Errorf("command failed (%d): %s", code, strings.Join(cmd, " "))
	}
	return nil
}

func portText(ports []int) string {
	return portTextOf(ports)
}

func portTextOf(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d/tcp", p)
	}
	return strings.Join(parts, " and ")
}

func defaultRun(cmd []string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Stdin = nil
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = io.Discard
	err := c.Run()
	if err == nil {
		return 0, buf.String()
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return 127, ""
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), buf.String()
	}
	return 1, ""
}

func defaultRead(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func linuxDefaultInterface() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return defaultInterfaceFromProc(string(b))
}

func defaultInterfaceFromProc(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return ""
	}
	best := ""
	bestMetric := 0
	have := false
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		flags, err1 := strconv.ParseInt(fields[3], 16, 64)
		metric, err2 := strconv.Atoi(fields[6])
		if err1 != nil || err2 != nil || flags&rtfUp == 0 {
			continue
		}
		if !have || metric < bestMetric {
			have = true
			bestMetric = metric
			best = fields[0]
		}
	}
	return best
}

func portSpecCovers(spec string, port int) bool {
	number, proto, _ := strings.Cut(spec, "/")
	if proto != "" && proto != "tcp" && proto != "any" {
		return false
	}
	lower := strings.ToLower(number)
	if lower == "any" || lower == "anywhere" {
		return true
	}
	number = strings.ReplaceAll(number, ":", "-")
	low, high, ranged := strings.Cut(number, "-")
	if ranged {
		lo, err1 := strconv.Atoi(low)
		hi, err2 := strconv.Atoi(high)
		if err1 != nil || err2 != nil {
			return false
		}
		return lo <= port && port <= hi
	}
	n, err := strconv.Atoi(number)
	if err != nil {
		return false
	}
	return n == port
}

func shellConfigValue(text, key string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && name == key {
			return strings.Trim(strings.TrimSpace(value), `"'`), true
		}
	}
	return "", false
}

func checkFirewalld(run Runner, ports []int, iface string) (Report, bool) {
	status, out := run([]string{"firewall-cmd", "--state"})
	if status != 0 || strings.TrimSpace(out) != "running" {
		return Report{}, false
	}
	zone := firewalldZone(run, iface)
	listStatus, listed := 1, ""
	if zone != "" {
		listStatus, listed = run([]string{"firewall-cmd", "--zone=" + zone, "--list-ports"})
	}
	if zone == "" || listStatus != 0 {
		return Report{
			Status:   "unknown",
			Firewall: "firewalld",
			Commands: [][]string{{"sudo", "firewall-cmd", "--list-all"}},
			Detail:   "firewalld is running, but its rules could not be read without root.",
		}, true
	}
	specs := strings.Fields(listed)
	var blocked []int
	for _, p := range ports {
		covered := false
		for _, s := range specs {
			if portSpecCovers(s, p) {
				covered = true
				break
			}
		}
		if !covered {
			blocked = append(blocked, p)
		}
	}
	if len(blocked) == 0 {
		return Report{Status: "open", Firewall: "firewalld", Detail: "zone " + zone}, true
	}
	add := []string{"sudo", "firewall-cmd", "--zone=" + zone, "--permanent"}
	for _, p := range blocked {
		add = append(add, fmt.Sprintf("--add-port=%d/tcp", p))
	}
	return Report{
		Status:       "blocked",
		Firewall:     "firewalld",
		BlockedPorts: blocked,
		Commands:     [][]string{add, {"sudo", "firewall-cmd", "--reload"}},
		Detail:       "zone " + zone,
	}, true
}

func firewalldZone(run Runner, iface string) string {
	if iface != "" {
		status, out := run([]string{"firewall-cmd", "--get-zone-of-interface=" + iface})
		if status == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out)
		}
	}
	status, out := run([]string{"firewall-cmd", "--get-default-zone"})
	if status == 0 && strings.TrimSpace(out) != "" {
		return strings.TrimSpace(out)
	}
	return ""
}

func ufwAllowedSpecsFromRules(text string) []string {
	var specs []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "###" || fields[1] != "tuple" || fields[2] != "###" {
			continue
		}
		action, proto, port := fields[3], fields[4], fields[5]
		if action != "allow" || fields[len(fields)-1] != "in" {
			continue
		}
		for _, p := range strings.Split(port, ",") {
			specs = append(specs, p+"/"+proto)
		}
	}
	return specs
}

var ufwStatusSpec = regexp.MustCompile(`^(\S+)\s+(?:\(v6\)\s+)?ALLOW(?: IN)?\s`)

func ufwAllowedSpecsFromStatus(text string) []string {
	var specs []string
	for _, line := range strings.Split(text, "\n") {
		match := ufwStatusSpec.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		specs = append(specs, strings.Split(match[1], ",")...)
	}
	return specs
}

func checkUfw(run Runner, read Reader, ports []int) (Report, bool) {
	conf, ok := read(ufwConf)
	enabled, _ := shellConfigValue(conf, "ENABLED")
	if !ok || !strings.EqualFold(enabled, "yes") {
		return Report{}, false
	}
	defaults, _ := read(ufwDefaults)
	policy, _ := shellConfigValue(defaults, "DEFAULT_INPUT_POLICY")
	if policy == "ACCEPT" {
		return Report{Status: "open", Firewall: "ufw", Detail: "default incoming policy is allow"}, true
	}

	var specs []string
	known := false
	if rules, ok := read(ufwUserRules); ok {
		specs = ufwAllowedSpecsFromRules(rules)
		known = true
	} else {
		status, out := run([]string{"sudo", "-n", "ufw", "status"})
		if status == 0 {
			specs = ufwAllowedSpecsFromStatus(out)
			known = true
		}
	}

	allowCmds := make([][]string, len(ports))
	for i, p := range ports {
		allowCmds[i] = []string{"sudo", "ufw", "allow", fmt.Sprintf("%d/tcp", p)}
	}
	if !known {
		return Report{
			Status:       "unknown",
			Firewall:     "ufw",
			BlockedPorts: append([]int(nil), ports...),
			Commands:     allowCmds,
			Detail:       "ufw is enabled, but its rules could not be read without root.",
		}, true
	}
	var blocked []int
	for _, p := range ports {
		covered := false
		for _, s := range specs {
			if portSpecCovers(s, p) {
				covered = true
				break
			}
		}
		if !covered {
			blocked = append(blocked, p)
		}
	}
	if len(blocked) == 0 {
		return Report{Status: "open", Firewall: "ufw"}, true
	}
	cmds := make([][]string, len(blocked))
	for i, p := range blocked {
		cmds[i] = []string{"sudo", "ufw", "allow", fmt.Sprintf("%d/tcp", p)}
	}
	return Report{
		Status:       "blocked",
		Firewall:     "ufw",
		BlockedPorts: blocked,
		Commands:     cmds,
	}, true
}

func checkRawServices(run Runner) (Report, bool) {
	for _, service := range rawFirewallServices {
		status, out := run([]string{"systemctl", "is-active", service + ".service"})
		if status == 0 && strings.TrimSpace(out) == "active" {
			return Report{
				Status:   "unknown",
				Firewall: service,
				Commands: [][]string{{"sudo", "nft", "list", "ruleset"}},
				Detail:   fmt.Sprintf("The %s service is active; its rules can only be read as root.", service),
			}, true
		}
	}
	return Report{}, false
}
