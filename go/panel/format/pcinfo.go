package format

import (
	"strings"

	"kidpcmonitor/panel/pyval"
)

// legacyAccessStatus is the access label for agents that do not report
// access_status.
func legacyAccessStatus(status any, manualLock bool) string {
	if manualLock {
		return "Locked — manual lock"
	}
	if status == "LOCKED" {
		return "Screen locked"
	}
	return "Unlocked"
}

// SettingsToPCInfo converts an agent "get settings" payload into the panel's
// PC-info dict (remote_client.settings_to_pc_info). hostnameFallback "" means
// None. It returns a *pyval.Error where Python raises (values a well-behaved
// agent never sends).
func SettingsToPCInfo(settings map[string]any, host, hostnameFallback string) (map[string]any, error) {
	status := pyval.Or(settings["status"], "UNKNOWN")
	dailyLimit := settings["daily_limit"]
	bedTime := settings["bed_time"]
	wakeTime := settings["wake_time"]
	extension, err := pyval.Int(pyval.Or(settings["cumulative_extension"], int64(0)))
	if err != nil {
		return nil, err
	}
	accumulated, err := pyval.Int(pyval.Or(settings["accumulated_seconds"], int64(0)))
	if err != nil {
		return nil, err
	}

	var timeRemaining any
	if remaining := settings["time_remaining"]; remaining != nil {
		timeRemaining = pyval.Str(remaining) + " minutes"
	}

	var lockTimes any
	if pyval.Truthy(bedTime) {
		lockTimes = []any{bedTime}
	}

	var effectiveLimit any
	if dailyLimit != nil || extension > 0 {
		base := pyval.Or(dailyLimit, int64(0))
		limit, ok := pyval.Number(base)
		if !ok {
			return nil, &pyval.Error{
				Type: "TypeError",
				Msg: "unsupported operand type(s) for +: " + pyval.Repr(pyval.TypeName(base)) +
					" and 'float'",
			}
		}
		effectiveLimit = limit + float64(extension)/60
	}

	var hostname any = settings["name"]
	if !pyval.Truthy(hostname) {
		hostname = hostnameFallback
		if hostnameFallback == "" {
			hostname = "PC at " + host
		}
	}

	manualLock := pyval.Truthy(settings["manual_lock"])
	enforcementActive := false
	if v := settings["enforcement_active"]; v != nil {
		enforcementActive = pyval.Truthy(v)
	}
	accessStatus := settings["access_status"]
	if accessStatus == nil {
		accessStatus = legacyAccessStatus(status, manualLock)
	}

	return map[string]any{
		"ip":                           host,
		"hostname":                     hostname,
		"status":                       status,
		"locked":                       status == "LOCKED",
		"current_user":                 settings["current_user"],
		"daily_limit":                  dailyLimit,
		"usage_limit":                  dailyLimit,
		"bed_time":                     bedTime,
		"lock_times":                   lockTimes,
		"wake_time":                    wakeTime,
		"manual_lock_active":           manualLock,
		"enforcement_active":           enforcementActive,
		"enforcement_reason":           settings["enforcement_reason"],
		"access_status":                accessStatus,
		"cumulative_extension_seconds": extension,
		"accumulated_seconds":          accumulated,
		"effective_limit_minutes":      effectiveLimit,
		"time_remaining":               timeRemaining,
		"reachable":                    true,
	}, nil
}

// DashboardStatusKey is the badge-level status used to coalesce registry
// updates: "cant_control", "not_connected", "locked" or "online".
func DashboardStatusKey(info map[string]any) string {
	if pyval.Truthy(info["connection_error"]) {
		return "cant_control"
	}
	reachable := true
	if v, ok := info["reachable"]; ok {
		reachable = pyval.Truthy(v)
	}
	if pyval.Truthy(info["agent_not_running"]) || !reachable {
		return "not_connected"
	}
	if pyval.Truthy(info["locked"]) {
		return "locked"
	}
	return "online"
}

// ActionFields are the protocol request fields for a panel action.
type ActionFields struct {
	Action string
	Var    *string // nil: no var
	Val    any     // nil: no val
	Tail   *int64  // nil: no tail
}

func strPtr(s string) *string { return &s }

// ActionRequestFields maps a panel action name and its JSON payload to
// protocol request fields (remote_client.action_request_fields). It returns
// a *pyval.Error where Python raises: KeyError for an unknown action or a
// missing "minutes", ValueError/TypeError for a bad number.
func ActionRequestFields(actionName string, payload map[string]any) (ActionFields, error) {
	p := payload
	if p == nil {
		p = map[string]any{}
	}
	get := func(key string, fallback any) any {
		if v, ok := p[key]; ok {
			return v
		}
		return fallback
	}
	switch actionName {
	case "lock":
		return ActionFields{Action: "lock"}, nil
	case "shutdown":
		return ActionFields{Action: "shutdown"}, nil
	case "message":
		return ActionFields{Action: "message", Val: get("message", "")}, nil
	case "extend_time":
		raw, ok := p["minutes"]
		if !ok {
			return ActionFields{}, pyval.KeyError("minutes")
		}
		n, err := pyval.Int(raw)
		if err != nil {
			return ActionFields{}, err
		}
		return ActionFields{Action: "extend", Val: n}, nil
	case "clear_manual_lock":
		return ActionFields{Action: "clear", Var: strPtr("manual_lock")}, nil
	case "clear_extensions":
		return ActionFields{Action: "clear", Var: strPtr("cumulative_extension")}, nil
	case "set_daily_limit":
		minutes := p["minutes"]
		if minutes == nil || minutes == "" {
			return ActionFields{Action: "clear", Var: strPtr("daily_limit")}, nil
		}
		n, err := pyval.Int(minutes)
		if err != nil {
			return ActionFields{}, err
		}
		return ActionFields{Action: "set", Var: strPtr("daily_limit"), Val: n}, nil
	case "set_bed_time":
		return ActionFields{Action: "set", Var: strPtr("bed_time"), Val: p["time"]}, nil
	case "clear_bed_time", "clear_lock_times":
		return ActionFields{Action: "clear", Var: strPtr("bed_time")}, nil
	case "set_wake_time":
		return ActionFields{Action: "set", Var: strPtr("wake_time"), Val: p["time"]}, nil
	case "clear_usage_limit":
		return ActionFields{Action: "clear", Var: strPtr("daily_limit")}, nil
	case "get_logs":
		n, err := pyval.Int(pyval.Or(p["tail"], int64(DefaultLogTailLines)))
		if err != nil {
			return ActionFields{}, err
		}
		return ActionFields{Action: "get_logs", Tail: &n}, nil
	}
	return ActionFields{}, pyval.KeyError(actionName)
}

// InvalidActionMessage is the text the panel shows when ActionRequestFields
// fails (PanelReverseServer.perform_action).
func InvalidActionMessage(actionName string, err error) string {
	return "Invalid value for " + actionName + ": " + err.Error()
}

// FormatAgentConnectionError turns low-level agent/client error text into
// parent-friendly text.
func FormatAgentConnectionError(message string) string {
	text := pyval.Strip(message)
	lower := strings.ToLower(text)

	if strings.Contains(lower, "timestamp outside allowed window") ||
		strings.Contains(lower, "stale_timestamp") {
		return "This PC's clock is out of sync (common after sleep or pausing a VM). " +
			"Correct the date and time on that computer, then try again."
	}
	if strings.Contains(lower, "no shared secret is configured") {
		return "No shared secret is configured on this computer. " +
			"Re-run the installer on the kid PC and web panel host."
	}
	if strings.Contains(lower, "authentication_failed") ||
		strings.Contains(lower, "signature did not verify") {
		return "Authentication failed — the shared secret on this panel may not match " +
			"the kid PC. Re-run the installers with the same secret."
	}
	const marker = ": "
	if idx := strings.LastIndex(text, marker); idx != -1 &&
		strings.Contains(lower, "cannot reach agent at") {
		detail := pyval.Strip(text[idx+len(marker):])
		if detail != "" && strings.ToLower(detail) != lower {
			return FormatAgentConnectionError(detail)
		}
	}
	if text == "" {
		return "Could not communicate with the agent."
	}
	return text
}
