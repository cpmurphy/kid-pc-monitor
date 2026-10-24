//go:build windows

package winplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"kidpcmonitor/netinfo"
)

// ConnectivityInfo is what the agent knows about itself for the start-up
// connectivity log.
type ConnectivityInfo struct {
	User       string
	Executable string
	LogFile    string
	LogLevel   string // Python level name
}

const profilesScript = "@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | " +
	"Select-Object InterfaceAlias, IPv4Connectivity, NetworkCategory) | " +
	"ConvertTo-Json -Compress"

// LogConnectivityDiagnostics logs the process, primary IPv4 and Windows
// network profiles (a Public profile is the usual reason the panel cannot be
// reached), as WindowsHostPlatform.log_connectivity_diagnostics does.
func (p *Platform) LogConnectivityDiagnostics(log *slog.Logger, info ConnectivityInfo) {
	ip := netinfo.PrimaryIPv4()
	if ip == "" {
		ip = "none"
	}
	log.Info(fmt.Sprintf("Connectivity check: pid=%d user=%s primary_ip=%s exe=%s log=%s level=%s",
		os.Getpid(), info.User, ip, info.Executable, info.LogFile, info.LogLevel))
	log.Info("Agent connects outbound to the parent web panel (discovery on TCP 5000, " +
		"reverse control on TCP 9998); no inbound agent listen port is required.")

	profiles, err := networkProfiles()
	if err != nil {
		log.Debug("PowerShell diagnostic failed: " + err.Error())
	}
	if profiles == nil {
		log.Warn("Could not read Windows network profiles (Get-NetConnectionProfile)")
		return
	}
	for _, entry := range profiles {
		log.Info(fmt.Sprintf("Network profile: interface=%s connectivity=%s category=%s",
			field(entry, "InterfaceAlias"), field(entry, "IPv4Connectivity"), field(entry, "NetworkCategory")))
	}
}

// networkProfiles runs Get-NetConnectionProfile without a console window.
// It returns nil when PowerShell prints nothing.
func networkProfiles() ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", profilesScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseProfiles(out)
}

// parseProfiles accepts ConvertTo-Json output: one object or an array.
func parseProfiles(out []byte) ([]map[string]any, error) {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil, nil
	}
	if strings.HasPrefix(text, "{") {
		var one map[string]any
		if err := json.Unmarshal([]byte(text), &one); err != nil {
			return nil, err
		}
		return []map[string]any{one}, nil
	}
	var many []map[string]any
	if err := json.Unmarshal([]byte(text), &many); err != nil {
		return nil, err
	}
	return many, nil
}

// field formats a profile value as Python's %s would.
func field(entry map[string]any, key string) string {
	v, ok := entry[key]
	switch {
	case !ok:
		return "?"
	case v == nil:
		return "None"
	}
	if f, isNum := v.(float64); isNum && f == float64(int64(f)) {
		return fmt.Sprint(int64(f))
	}
	return fmt.Sprint(v)
}
