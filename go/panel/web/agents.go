package web

import (
	"context"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/panel/store"
)

// RecordReverseStatus stores a reverse agent's settings report
// (web_panel._record_reverse_pc_info): the heartbeat, the dashboard poll
// snapshot, the tracked-PC registry and, with someone signed in, the day's
// usage snapshot. It is reverse.Server's OnStatus.
func (a *App) RecordReverseStatus(hostname, ip string, settings map[string]any) {
	info, err := format.SettingsToPCInfo(settings, ip, hostname)
	if err != nil {
		a.log.Warn("Failed to convert reverse status", "host", hostname, "err", err)
		return
	}
	info["ip"] = ip
	if err := a.store.RecordAgentPoll(hostname, ip, info); err != nil {
		a.log.Warn("Failed to persist reverse heartbeat", "host", hostname, "err", err)
		return
	}
	err = a.store.SavePollSnapshot(info)
	if err == nil {
		err = a.store.RecordPollInspect(ip, info, time.Time{})
	}
	if err == nil && pyval.Truthy(info["current_user"]) {
		err = a.store.SaveSnapshot(info)
	}
	if err != nil {
		a.log.Warn("Failed to persist reverse status", "host", hostname, "err", err)
	}
}

// RecordReverseDisconnect marks a reverse agent offline as soon as its
// session ends (web_panel._record_reverse_disconnect). It is
// reverse.Server's OnDisconnect.
func (a *App) RecordReverseDisconnect(hostname, ip string) {
	if err := a.store.ClearAgentForHostname(hostname); err != nil {
		a.log.Warn("Failed to clear reverse heartbeat", "host", hostname, "err", err)
		return
	}
	failure := map[string]any{"hostname": hostname, "ip": ip, "reachable": false}
	if err := a.store.RecordPollInspect(ip, failure, time.Time{}); err != nil {
		a.log.Warn("Failed to persist reverse disconnect", "host", hostname, "err", err)
	}
}

// Pruner timing (agent_poller.py).
const (
	pruneInitialMin = 5 * time.Second
	pruneInitialMax = 55 * time.Second
)

// RunPruner removes stale tracked PCs about every PollIntervalSec, after a
// random 5-55 s start delay, until ctx ends (agent_poller.start_agent_poller).
func RunPruner(ctx context.Context, s *store.Store, a *App) {
	interval := float64(PollIntervalSec)
	wait := pruneInitialMin + time.Duration(rand.Float64()*float64(pruneInitialMax-pruneInitialMin))
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		pruned, err := s.PruneStaleTrackedIPs(0)
		switch {
		case err != nil:
			a.log.Error("Agent registry prune cycle failed", "err", err)
		case len(pruned) > 0:
			sort.Strings(pruned)
			a.log.Info("Pruned stale tracked PC(s): " + strings.Join(pruned, ", "))
		default:
			a.log.Debug("Agent registry prune cycle finished (none stale)")
		}
		jitter := min(interval*0.1, 5.0)
		wait = time.Duration((interval - jitter + rand.Float64()*2*jitter) * float64(time.Second))
	}
}
