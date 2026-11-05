package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // IANA zones on every OS (the DST scenario)

	"kidpcmonitor/panel/pyval"
)

// The golden vectors are generated from the Python stores by
// tests/panelstore_vectors_gen.py. Every scenario is replayed here on a
// fresh panel.db, and after every step both the query results and the table
// contents must agree with Python's.

type obj = map[string]any

func loadVectors(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "panelstore", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyval.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(obj)
}

func str(v any) string { s, _ := v.(string); return s }

func list(v any) []any { l, _ := v.([]any); return l }

func makeLoc(t *testing.T, spec string) *time.Location {
	t.Helper()
	if spec[0] == '+' || spec[0] == '-' {
		h, _ := strconv.Atoi(spec[1:3])
		m, _ := strconv.Atoi(spec[4:6])
		off := h*3600 + m*60
		if spec[0] == '-' {
			off = -off
		}
		return time.FixedZone("", off)
	}
	loc, err := time.LoadLocation(spec)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, aware, err := pyval.FromISOFormat(s)
	if err != nil || !aware {
		t.Fatalf("bad time %q: %v", s, err)
	}
	return tm
}

func TestConstants(t *testing.T) {
	c := loadVectors(t)["constants"].(obj)
	want := obj{
		"stale_tracked_hours":  int64(StaleTrackedHours),
		"retention_days":       int64(RetentionDays),
		"trim_interval_days":   int64(TrimIntervalDays),
		"recent_agent_seconds": int64(RecentAgentSeconds),
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("constants = %v, want %v", c, want)
	}
}

func TestScenarios(t *testing.T) {
	for _, raw := range list(loadVectors(t)["scenarios"]) {
		sc := raw.(obj)
		t.Run(str(sc["name"]), func(t *testing.T) { runScenario(t, sc) })
	}
}

func runScenario(t *testing.T, sc obj) {
	path := filepath.Join(t.TempDir(), DBFilename)
	if legacy := list(sc["legacy_sql"]); len(legacy) > 0 {
		raw, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range legacy {
			if _, err := raw.Exec(str(stmt)); err != nil {
				t.Fatalf("legacy sql %q: %v", stmt, err)
			}
		}
		raw.Close()
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Loc = makeLoc(t, str(sc["tz"]))
	queries := sc["queries"].(obj)

	for i, rawStep := range list(sc["steps"]) {
		st := rawStep.(obj)
		at := mustTime(t, str(st["at"]))
		s.Now = func() time.Time { return at }
		label := fmt.Sprintf("step %d (%s %s)", i, st["at"], st["op"])

		result, err := runOp(t, s, str(st["op"]), st["args"].(obj))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !reflect.DeepEqual(result, st["result"]) {
			t.Fatalf("%s: result %#v, want %#v", label, result, st["result"])
		}
		state, err := queryState(s, queries)
		if err != nil {
			t.Fatalf("%s: state: %v", label, err)
		}
		if diff := firstDiff("state", state, st["state"]); diff != "" {
			t.Fatalf("%s: %s", label, diff)
		}
	}
}

func runOp(t *testing.T, s *Store, op string, args obj) (any, error) {
	info, _ := args["pc_info"].(obj)
	switch op {
	case "noop":
		return nil, nil
	case "record_poll_inspect":
		var when time.Time
		if w, ok := args["when"]; ok {
			when = mustTime(t, str(w))
		}
		return nil, s.RecordPollInspect(str(args["ip"]), info, when)
	case "save_snapshot":
		return nil, s.SaveSnapshot(info)
	case "save_poll_snapshot":
		return nil, s.SavePollSnapshot(info)
	case "maybe_trim_old_rows":
		return nil, s.MaybeTrimOldRows()
	case "record_agent_poll":
		return nil, s.RecordAgentPoll(str(args["hostname"]), str(args["ip"]), info)
	case "clear_agent_for_ip":
		return nil, s.ClearAgentForIP(str(args["ip"]))
	case "clear_agent_for_hostname":
		return nil, s.ClearAgentForHostname(str(args["hostname"]))
	case "prune_stale_tracked_ips":
		var maxAge time.Duration
		if h, ok := pyval.Number(args["max_age_hours"]); ok {
			maxAge = time.Duration(h * float64(time.Hour))
		}
		pruned, err := s.PruneStaleTrackedIPs(maxAge)
		sort.Strings(pruned)
		out := []any{}
		for _, ip := range pruned {
			out = append(out, ip)
		}
		return out, err
	case "sql":
		_, err := s.db.Exec(str(args["sql"]), list(args["params"])...)
		return nil, err
	}
	t.Fatalf("unknown op %q", op)
	return nil, nil
}

func iso(t time.Time, ok bool) any {
	if !ok {
		return nil
	}
	return pyval.ISOFormat(t, true)
}

func infoOrNil(info Info) any {
	if info == nil {
		return nil
	}
	return info
}

func snapOut(snap *Snapshot) any {
	if snap == nil {
		return nil
	}
	return []any{snap.RecordedAt, snap.Payload}
}

func pcsOut(pcs []TrackedPC) []any {
	out := []any{}
	for _, pc := range pcs {
		out = append(out, []any{pc.IP, pc.Info})
	}
	return out
}

func usageOut(groups []UsageGroup) []any {
	out := []any{}
	for _, g := range groups {
		days := []any{}
		for _, d := range g.Days {
			days = append(days, d)
		}
		out = append(out, obj{"hostname": g.Hostname, "days": days})
	}
	return out
}

func queryState(s *Store, queries obj) (obj, error) {
	tracked, err := s.TrackedIPs()
	if err != nil {
		return nil, err
	}
	pcs, lastPoll, err := s.DashboardPCs()
	if err != nil {
		return nil, err
	}
	var lastPollOut any
	if lastPoll != nil {
		lastPollOut = pyval.ISOFormat(*lastPoll, true)
	}
	contact, err := s.TrackedIPContactTimes()
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(contact))
	for ip := range contact {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	contactOut := []any{}
	for _, ip := range ips {
		contactOut = append(contactOut, []any{ip, pyval.ISOFormat(contact[ip], true)})
	}
	tables, err := dumpTables(s.db)
	if err != nil {
		return nil, err
	}
	state := obj{
		"tracked":       pcsOut(tracked),
		"dashboard":     obj{"pcs": pcsOut(pcs), "last_poll_at": lastPollOut},
		"contact_times": contactOut,
		"by_ip":         obj{},
		"by_hostname":   obj{},
		"by_user":       obj{},
		"panel_lookups": []any{},
		"tables":        tables,
	}
	for _, rawIP := range list(queries["ips"]) {
		ip := str(rawIP)
		scanPC, err := s.ScanPC(ip)
		if err != nil {
			return nil, err
		}
		updated, ok, err := s.PCPollUpdatedAt(ip)
		if err != nil {
			return nil, err
		}
		latest, err := s.LatestSnapshotForPC("", ip, false)
		if err != nil {
			return nil, err
		}
		reachable, err := s.LatestSnapshotForPC("", ip, true)
		if err != nil {
			return nil, err
		}
		panelSnap, err := s.LatestPanelSnapshotForPC("", ip)
		if err != nil {
			return nil, err
		}
		agent, err := s.RecentAgentForIP(ip, 0)
		if err != nil {
			return nil, err
		}
		state["by_ip"].(obj)[ip] = obj{
			"scan_pc":                   infoOrNil(scanPC),
			"poll_updated_at":           iso(updated, ok),
			"latest_snapshot":           snapOut(latest),
			"latest_reachable_snapshot": snapOut(reachable),
			"latest_panel_snapshot":     snapOut(panelSnap),
			"recent_agent":              infoOrNil(agent),
		}
	}
	for _, rawHost := range list(queries["hostnames"]) {
		host := str(rawHost)
		scanPC, err := s.ScanPCByHostname(host)
		if err != nil {
			return nil, err
		}
		latest, err := s.LatestSnapshotForPC(host, "", false)
		if err != nil {
			return nil, err
		}
		agent, err := s.RecentAgentForHostname(host, 0)
		if err != nil {
			return nil, err
		}
		state["by_hostname"].(obj)[host] = obj{
			"scan_pc":         infoOrNil(scanPC),
			"latest_snapshot": snapOut(latest),
			"recent_agent":    infoOrNil(agent),
		}
	}
	for _, rawUser := range list(queries["users"]) {
		user := str(rawUser)
		week, err := s.UsageHistoryForUser(user, 7)
		if err != nil {
			return nil, err
		}
		two, err := s.UsageHistoryForUser(user, 2)
		if err != nil {
			return nil, err
		}
		state["by_user"].(obj)[user] = obj{"usage_7": usageOut(week), "usage_2": usageOut(two)}
	}
	for _, rawLookup := range list(queries["panel_lookups"]) {
		lookup := list(rawLookup)
		snap, err := s.LatestPanelSnapshotForPC(str(lookup[0]), str(lookup[1]))
		if err != nil {
			return nil, err
		}
		state["panel_lookups"] = append(state["panel_lookups"].([]any), []any{lookup[0], lookup[1], snapOut(snap)})
	}
	return state, nil
}

// dumpTables mirrors dump_tables in the generator.
func dumpTables(db *sql.DB) (obj, error) {
	rows := func(query string, payloadIndex int) ([]any, error) {
		r, err := db.Query(query)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		cols, _ := r.Columns()
		out := []any{}
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				return nil, err
			}
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			if payloadIndex >= 0 {
				p, err := pyval.DecodeJSON([]byte(vals[payloadIndex].(string)))
				if err != nil {
					return nil, err
				}
				vals[payloadIndex] = p
			}
			out = append(out, vals)
		}
		return out, r.Err()
	}
	tables := obj{}
	for name, q := range map[string]struct {
		sql     string
		payload int
	}{
		"snapshots": {"SELECT username, hostname, ip, snapshot_date, recorded_at, payload_json" +
			" FROM snapshots ORDER BY username, hostname, snapshot_date", 5},
		"scans":          {"SELECT id, scanned_at, network_label, subnet, error FROM scans ORDER BY id", -1},
		"scan_pcs":       {"SELECT scan_id, ip, hostname, payload_json FROM scan_pcs ORDER BY scan_id, ip", 3},
		"panel_meta":     {"SELECT key, value FROM panel_meta ORDER BY key", -1},
		"reverse_agents": {"SELECT hostname, ip, last_seen, payload_json FROM reverse_agents ORDER BY hostname", 3},
	} {
		r, err := rows(q.sql, q.payload)
		if err != nil {
			return nil, err
		}
		tables[name] = r
	}
	return tables, nil
}

// firstDiff describes the first place got and want differ, or "".
func firstDiff(path string, got, want any) string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: got %T %#v, want object", path, got, got)
		}
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			gv, gok := g[k]
			wv, wok := w[k]
			if gok != wok {
				return fmt.Sprintf("%s.%s: present in got=%v want=%v (got %#v, want %#v)", path, k, gok, wok, gv, wv)
			}
			if d := firstDiff(path+"."+k, gv, wv); d != "" {
				return d
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: got %T %#v, want list", path, got, got)
		}
		for i := 0; i < len(w) && i < len(g); i++ {
			if d := firstDiff(fmt.Sprintf("%s[%d]", path, i), g[i], w[i]); d != "" {
				return d
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("%s: got %d items, want %d\n got  %s\n want %s", path, len(g), len(w), short(g), short(w))
		}
		return ""
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("%s: got %#v, want %#v", path, got, want)
	}
	return ""
}

func short(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}
