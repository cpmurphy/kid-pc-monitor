package store

import (
	"database/sql"
	"sort"
	"strings"
	"time"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
)

// Snapshot retention (snapshot_store.py).
const (
	MetaLastTrimAt   = "last_trim_at"
	RetentionDays    = 7
	TrimIntervalDays = 7
)

// Snapshot is a stored snapshot row: its recorded_at text and payload.
type Snapshot struct {
	RecordedAt string
	Payload    Info
}

func snapshotUsername(info Info) string {
	if u, ok := info["current_user"].(string); ok {
		return u
	}
	return ""
}

const upsertSnapshotSQL = `INSERT OR REPLACE INTO snapshots
    (username, hostname, ip, snapshot_date, recorded_at, payload_json)
VALUES (?, ?, ?, ?, ?, ?)`

// SaveSnapshot persists a reachable inspect result for a signed-in user: the
// latest per user, PC and calendar day (snapshot_store.save_snapshot). It
// then trims old rows when a trim is due.
func (s *Store) SaveSnapshot(info Info) error {
	if !pyval.Truthy(info["reachable"]) {
		return nil
	}
	username := snapshotUsername(info)
	hostname := info["hostname"]
	if username == "" || !pyval.Truthy(hostname) {
		return nil
	}
	ip := textValue(pyval.Or(info["ip"], ""))
	now := s.now()
	payloadJSON, err := encodePayload(info)
	if err != nil {
		return err
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(upsertSnapshotSQL, username, textValue(hostname), ip,
			now.Format("2006-01-02"), pyval.ISOFormatSeconds(now, true), payloadJSON); err != nil {
			return err
		}
		return s.trimOldRows(tx)
	})
}

// SavePollSnapshot persists a reachable poll result for dashboard display
// (snapshot_store.save_poll_snapshot); unreachable results are skipped so
// they never replace the day's last reachable snapshot.
func (s *Store) SavePollSnapshot(info Info) error {
	if !pyval.Truthy(get(info, "reachable", true)) {
		return nil
	}
	ipValue := info["ip"]
	if !pyval.Truthy(ipValue) {
		return nil
	}
	ip := textValue(ipValue)
	hostname := pyval.Or(info["hostname"], "PC at "+ip)
	username := snapshotUsername(info)
	now := s.now()
	payloadJSON, err := encodePayload(merge(info, Info{"ip": ipValue, "hostname": hostname}))
	if err != nil {
		return err
	}
	_, err = s.exec(upsertSnapshotSQL, username, textValue(hostname), ip,
		now.Format("2006-01-02"), pyval.ISOFormatSeconds(now, true), payloadJSON)
	return err
}

var statusRank = map[string]int{"online": 3, "locked": 3, "not_connected": 1, "cant_control": 0}

// dedupeHostname is the key duplicate dashboard cards are grouped by, or ""
// when only a placeholder hostname is known.
func dedupeHostname(info Info, ip string) string {
	h, ok := info["hostname"].(string)
	if !ok || h == "" || h == "PC at "+ip {
		return ""
	}
	return strings.ToLower(h)
}

// dedupeByHostname collapses one PC seen at several IPs, keeping the IP with
// the most recent successful contact, then the most controllable status,
// then the greatest IP.
func dedupeByHostname(dashboard []TrackedPC, contact map[string]time.Time) []TrackedPC {
	epoch := time.Unix(0, 0)
	byIP := map[string]Info{}
	for _, pc := range dashboard {
		byIP[pc.IP] = pc.Info
	}
	greater := func(a, b string) bool {
		ta, ok := contact[a]
		if !ok {
			ta = epoch
		}
		tb, ok := contact[b]
		if !ok {
			tb = epoch
		}
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
		ra := statusRank[format.DashboardStatusKey(byIP[a])]
		rb := statusRank[format.DashboardStatusKey(byIP[b])]
		if ra != rb {
			return ra > rb
		}
		return a > b
	}
	best := map[string]string{}
	for _, pc := range dashboard {
		host := dedupeHostname(pc.Info, pc.IP)
		if host == "" {
			continue
		}
		if cur, ok := best[host]; !ok || greater(pc.IP, cur) {
			best[host] = pc.IP
		}
	}
	keep := map[string]bool{}
	for _, ip := range best {
		keep[ip] = true
	}
	var out []TrackedPC
	for _, pc := range dashboard {
		if dedupeHostname(pc.Info, pc.IP) == "" || keep[pc.IP] {
			out = append(out, pc)
		}
	}
	return out
}

// DashboardPCs returns the tracked PCs for the dashboard, overlaid with each
// one's latest snapshot, and the newest snapshot time (nil when none)
// (snapshot_store.get_dashboard_pcs).
func (s *Store) DashboardPCs() ([]TrackedPC, *time.Time, error) {
	tracked, err := s.TrackedIPs()
	if err != nil {
		return nil, nil, err
	}
	var dashboard []TrackedPC
	var lastPollAt *time.Time
	for _, pc := range tracked {
		entry := pc.Info
		if !pyval.Truthy(get(entry, "reachable", true)) || pyval.Truthy(entry["connection_error"]) {
			dashboard = append(dashboard, TrackedPC{pc.IP, merge(entry, Info{"ip": pc.IP})})
			continue
		}
		snap, err := s.LatestSnapshotForPC("", pc.IP, false)
		if err != nil {
			return nil, nil, err
		}
		var info Info
		if snap != nil {
			info = merge(snap.Payload, Info{"ip": pc.IP, "snapshot_recorded_at": snap.RecordedAt})
			t, err := s.parseTime(snap.RecordedAt)
			if err != nil {
				return nil, nil, err
			}
			if lastPollAt == nil || t.After(*lastPollAt) {
				lastPollAt = &t
			}
		} else {
			info = merge(entry, Info{"ip": pc.IP})
		}
		dashboard = append(dashboard, TrackedPC{pc.IP, info})
	}
	contact, err := s.TrackedIPContactTimes()
	if err != nil {
		return nil, nil, err
	}
	return dedupeByHostname(dashboard, contact), lastPollAt, nil
}

// snapshotHasPanelData is true when a snapshot carries a full inspect result,
// not a bare failure.
func snapshotHasPanelData(payload Info) bool { return payload["status"] != nil }

// LatestSnapshotForPC returns the most recent snapshot by hostname, falling
// back to ip ("" means not given), or nil
// (snapshot_store.get_latest_snapshot_for_pc).
func (s *Store) LatestSnapshotForPC(hostname, ip string, reachableOnly bool) (*Snapshot, error) {
	if hostname != "" {
		snap, err := s.queryLatestSnapshot("hostname = ?", hostname, reachableOnly)
		if err != nil || snap != nil {
			return snap, err
		}
	}
	if ip != "" {
		return s.queryLatestSnapshot("ip = ?", ip, reachableOnly)
	}
	return nil, nil
}

// LatestPanelSnapshotForPC is the snapshot for the control page's stale-data
// fallback: the latest one if it carries panel data, else the latest
// reachable one (snapshot_store.get_latest_panel_snapshot_for_pc).
func (s *Store) LatestPanelSnapshotForPC(hostname, ip string) (*Snapshot, error) {
	snap, err := s.LatestSnapshotForPC(hostname, ip, false)
	if err != nil {
		return nil, err
	}
	if snap != nil && snapshotHasPanelData(snap.Payload) {
		return snap, nil
	}
	return s.LatestSnapshotForPC(hostname, ip, true)
}

func (s *Store) queryLatestSnapshot(clause, param string, reachableOnly bool) (*Snapshot, error) {
	rows, err := s.db.Query(`SELECT recorded_at, payload_json
        FROM snapshots
        WHERE `+clause+`
        ORDER BY recorded_at DESC`, param)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var recordedAt, raw string
		if err := rows.Scan(&recordedAt, &raw); err != nil {
			return nil, err
		}
		payload, err := decodePayload(raw)
		if err != nil {
			return nil, err
		}
		if reachableOnly && !pyval.Truthy(payload["reachable"]) {
			continue
		}
		return &Snapshot{RecordedAt: recordedAt, Payload: payload}, nil
	}
	return nil, rows.Err()
}

// UsageGroup is one PC's usage days, newest first.
type UsageGroup struct {
	Hostname string
	Days     []Info
}

// UsageHistoryForUser returns usage for the last days calendar days, newest
// first, grouped by hostname in sorted order; days without a snapshot are
// {"date", "no_data": true} (snapshot_store.get_usage_history_for_user).
func (s *Store) UsageHistoryForUser(username string, days int) ([]UsageGroup, error) {
	today := s.localToday()
	start := today.AddDate(0, 0, -(days - 1))
	rows, err := s.db.Query(`SELECT hostname, snapshot_date, recorded_at, payload_json
        FROM snapshots
        WHERE username = ? AND snapshot_date >= ? AND snapshot_date <= ?
        ORDER BY hostname, snapshot_date`,
		username, start.Format("2006-01-02"), today.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHost := map[string]map[string]Info{}
	for rows.Next() {
		var host, date, recordedAt, raw string
		if err := rows.Scan(&host, &date, &recordedAt, &raw); err != nil {
			return nil, err
		}
		payload, err := decodePayload(raw)
		if err != nil {
			return nil, err
		}
		entry, err := dayEntry(date, recordedAt, payload)
		if err != nil {
			return nil, err
		}
		if byHost[host] == nil {
			byHost[host] = map[string]Info{}
		}
		byHost[host][date] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	groups := make([]UsageGroup, 0, len(hosts))
	for _, host := range hosts {
		var groupDays []Info
		for offset := 0; offset < days; offset++ {
			key := today.AddDate(0, 0, -offset).Format("2006-01-02")
			if entry, ok := byHost[host][key]; ok {
				groupDays = append(groupDays, entry)
			} else {
				groupDays = append(groupDays, Info{"date": key, "no_data": true})
			}
		}
		groups = append(groups, UsageGroup{Hostname: host, Days: groupDays})
	}
	return groups, nil
}

func dayEntry(date, recordedAt string, payload Info) (Info, error) {
	accumulated, err := pyval.Int(pyval.Or(payload["accumulated_seconds"], int64(0)))
	if err != nil {
		return nil, err
	}
	extension, err := pyval.Int(pyval.Or(payload["cumulative_extension_seconds"], int64(0)))
	if err != nil {
		return nil, err
	}
	return Info{
		"date":                         date,
		"accumulated_seconds":          accumulated,
		"daily_limit":                  payload["daily_limit"],
		"cumulative_extension_seconds": extension,
		"time_remaining":               payload["time_remaining"],
		"remaining_minutes":            format.RemainingMinutes(payload["time_remaining"]),
		"recorded_at":                  recordedAt,
	}, nil
}

// MaybeTrimOldRows deletes snapshots older than RetentionDays, at most once
// every TrimIntervalDays (snapshot_store.maybe_trim_old_rows).
func (s *Store) MaybeTrimOldRows() error {
	return s.tx(s.trimOldRows)
}

func (s *Store) trimOldRows(tx *sql.Tx) error {
	now := s.now()
	last, ok, err := getMeta(tx, MetaLastTrimAt)
	if err != nil {
		return err
	}
	if ok && last != "" {
		lastTrim, err := s.parseTime(last)
		if err != nil {
			return err
		}
		if now.Sub(lastTrim) < TrimIntervalDays*24*time.Hour {
			return nil
		}
	}
	cutoff := s.localToday().AddDate(0, 0, -RetentionDays).Format("2006-01-02")
	if _, err := tx.Exec("DELETE FROM snapshots WHERE snapshot_date < ?", cutoff); err != nil {
		return err
	}
	return setMeta(tx, MetaLastTrimAt, pyval.ISOFormatSeconds(now, true))
}
