package store

import (
	"database/sql"
	"errors"
	"time"

	"kidpcmonitor/panel/format"
	"kidpcmonitor/panel/pyval"
)

// Registry constants (scan_store.py).
const (
	StaleTrackedHours = 12
	PollNetworkLabel  = "poll"
)

// TrackedPC is one entry of the tracked-PC registry, in Python's dict order.
type TrackedPC struct {
	IP   string
	Info Info
}

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// RecordPollInspect updates the registry from a reverse status update
// (scan_store.record_poll_inspect). When the PC's dashboard status is
// unchanged it rewrites the latest row in place and bumps its scan time;
// otherwise it starts a new scan row. A zero when means now.
func (s *Store) RecordPollInspect(ip string, info Info, when time.Time) error {
	now := when
	if now.IsZero() {
		now = s.now()
	}
	payload := merge(info, Info{"ip": ip})
	payloadJSON, err := encodePayload(payload)
	if err != nil {
		return err
	}
	var hostname any
	if h, ok := payload["hostname"].(string); ok && h != "" {
		hostname = h
	}
	status := format.DashboardStatusKey(payload)
	stamp := pyval.ISOFormatSeconds(now, true)

	return s.tx(func(tx *sql.Tx) error {
		scanID, existing, found, err := latestScanPCForIP(tx, ip)
		if err != nil {
			return err
		}
		if found && format.DashboardStatusKey(existing) == status {
			if _, err := tx.Exec("UPDATE scan_pcs SET hostname = ?, payload_json = ? WHERE scan_id = ? AND ip = ?",
				hostname, payloadJSON, scanID, ip); err != nil {
				return err
			}
			_, err := tx.Exec("UPDATE scans SET scanned_at = ? WHERE id = ?", stamp, scanID)
			return err
		}
		res, err := tx.Exec("INSERT INTO scans (scanned_at, network_label, subnet, error) VALUES (?, ?, ?, ?)",
			stamp, PollNetworkLabel, "", nil)
		if err != nil {
			return err
		}
		newID, err := res.LastInsertId()
		if err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO scan_pcs (scan_id, ip, hostname, payload_json) VALUES (?, ?, ?, ?)",
			newID, ip, hostname, payloadJSON)
		return err
	})
}

// latestScanPCForIP is _latest_scan_pc_for_ip / _latest_tracked_row.
func latestScanPCForIP(q queryer, ip string) (scanID int64, payload Info, found bool, err error) {
	var raw string
	err = q.QueryRow(`SELECT sp.scan_id, sp.payload_json
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY sp.scan_id DESC
        LIMIT 1`, ip).Scan(&scanID, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, err
	}
	payload, err = decodePayload(raw)
	if err != nil {
		return 0, nil, false, err
	}
	return scanID, payload, true, nil
}

// TrackedIPs returns every tracked PC's latest sighting, ordered by IP
// (scan_store.get_tracked_ips). The payloads are as stored.
func (s *Store) TrackedIPs() ([]TrackedPC, error) {
	return trackedIPs(s.db)
}

func trackedIPs(q queryer) ([]TrackedPC, error) {
	rows, err := q.Query(`SELECT sp.ip, sp.payload_json, sp.scan_id
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE s.error IS NULL
        ORDER BY sp.ip, sp.scan_id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrackedPC
	seen := map[string]bool{}
	for rows.Next() {
		var ip, raw string
		var scanID int64
		if err := rows.Scan(&ip, &raw, &scanID); err != nil {
			return nil, err
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		payload, err := decodePayload(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, TrackedPC{IP: ip, Info: payload})
	}
	return out, rows.Err()
}

// ScanPC returns the tracked PC at ip, or nil (scan_store.get_scan_pc).
func (s *Store) ScanPC(ip string) (Info, error) {
	tracked, err := s.TrackedIPs()
	if err != nil {
		return nil, err
	}
	for _, pc := range tracked {
		if pc.IP == ip {
			return pc.Info, nil
		}
	}
	return nil, nil
}

// PCPollUpdatedAt is when the tracked PC at ip was last updated
// (scan_store.get_pc_poll_updated_at); ok is false when it is not tracked.
func (s *Store) PCPollUpdatedAt(ip string) (t time.Time, ok bool, err error) {
	return s.latestScanTime(s.db, ip)
}

func (s *Store) latestScanTime(q queryer, ip string) (time.Time, bool, error) {
	var raw string
	err := q.QueryRow(`SELECT s.scanned_at
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY s.id DESC
        LIMIT 1`, ip).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := s.parseTime(raw)
	return t, err == nil, err
}

// ScanPCByHostname returns the latest tracked PC with this hostname
// (case-insensitive), with "ip" set, or nil (scan_store.get_scan_pc_by_hostname).
func (s *Store) ScanPCByHostname(hostname string) (Info, error) {
	var ip, raw string
	var scanID int64
	err := s.db.QueryRow(`SELECT sp.ip, sp.payload_json, sp.scan_id
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.hostname COLLATE NOCASE = ? AND s.error IS NULL
        ORDER BY sp.scan_id DESC, sp.ip
        LIMIT 1`, hostname).Scan(&ip, &raw, &scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	payload, err := decodePayload(raw)
	if err != nil {
		return nil, err
	}
	payload["ip"] = ip
	return payload, nil
}

// latestReachableSnapshotTime is the newest snapshot of ip whose payload is
// reachable.
func (s *Store) latestReachableSnapshotTime(q queryer, ip string) (time.Time, bool, error) {
	rows, err := q.Query(`SELECT recorded_at, payload_json
        FROM snapshots
        WHERE ip = ?
        ORDER BY recorded_at DESC`, ip)
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var recordedAt, raw string
		if err := rows.Scan(&recordedAt, &raw); err != nil {
			return time.Time{}, false, err
		}
		payload, err := decodePayload(raw)
		if err != nil {
			return time.Time{}, false, err
		}
		if pyval.Truthy(payload["reachable"]) {
			t, err := s.parseTime(recordedAt)
			return t, err == nil, err
		}
	}
	return time.Time{}, false, rows.Err()
}

// latestReachableScanTime is the newest registry row for ip marked reachable.
func (s *Store) latestReachableScanTime(q queryer, ip string) (time.Time, bool, error) {
	rows, err := q.Query(`SELECT s.scanned_at AS scanned_at, sp.payload_json AS payload_json
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE sp.ip = ? AND s.error IS NULL
        ORDER BY s.id DESC`, ip)
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var scannedAt, raw string
		if err := rows.Scan(&scannedAt, &raw); err != nil {
			return time.Time{}, false, err
		}
		payload, err := decodePayload(raw)
		if err != nil {
			return time.Time{}, false, err
		}
		if pyval.Truthy(get(payload, "reachable", true)) {
			t, err := s.parseTime(scannedAt)
			return t, err == nil, err
		}
	}
	return time.Time{}, false, rows.Err()
}

// trackedIPLastUpdated is when ip was last seen reachable, by registry row or
// snapshot (scan_store.tracked_ip_last_updated).
func (s *Store) trackedIPLastUpdated(q queryer, ip string) (time.Time, bool, error) {
	scanT, scanOK, err := s.latestReachableScanTime(q, ip)
	if err != nil {
		return time.Time{}, false, err
	}
	snapT, snapOK, err := s.latestReachableSnapshotTime(q, ip)
	if err != nil {
		return time.Time{}, false, err
	}
	switch {
	case scanOK && snapOK:
		if snapT.After(scanT) {
			return snapT, true, nil
		}
		return scanT, true, nil
	case scanOK:
		return scanT, true, nil
	case snapOK:
		return snapT, true, nil
	}
	return time.Time{}, false, nil
}

func distinctTrackedIPs(q queryer) ([]string, error) {
	rows, err := q.Query(`SELECT DISTINCT sp.ip
        FROM scan_pcs sp
        INNER JOIN scans s ON sp.scan_id = s.id
        WHERE s.error IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

// TrackedIPContactTimes is the last time each tracked IP actually answered
// (scan_store.get_tracked_ip_contact_times).
func (s *Store) TrackedIPContactTimes() (map[string]time.Time, error) {
	return s.contactTimes(s.db)
}

func (s *Store) contactTimes(q queryer) (map[string]time.Time, error) {
	ips, err := distinctTrackedIPs(q)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for _, ip := range ips {
		t, ok, err := s.trackedIPLastUpdated(q, ip)
		if err != nil {
			return nil, err
		}
		if ok {
			out[ip] = t
		}
	}
	return out, nil
}

// PruneStaleTrackedIPs removes tracked PCs with no reachable update within
// maxAge (0 means StaleTrackedHours) and returns their IPs
// (scan_store.prune_stale_tracked_ips). The sole known PC is kept and marked
// not connected instead.
func (s *Store) PruneStaleTrackedIPs(maxAge time.Duration) ([]string, error) {
	if maxAge == 0 {
		maxAge = StaleTrackedHours * time.Hour
	}
	cutoff := s.now().Add(-maxAge)
	var pruned []string
	err := s.tx(func(tx *sql.Tx) error {
		ips, err := distinctTrackedIPs(tx)
		if err != nil {
			return err
		}
		var stale []string
		for _, ip := range ips {
			last, ok, err := s.trackedIPLastUpdated(tx, ip)
			if err != nil {
				return err
			}
			if !ok || last.Before(cutoff) {
				stale = append(stale, ip)
			}
		}
		if len(ips) == 1 && len(stale) > 0 {
			return markLatestNotConnected(tx, ips[0])
		}
		for _, ip := range stale {
			if _, err := tx.Exec("DELETE FROM scan_pcs WHERE ip = ?", ip); err != nil {
				return err
			}
			pruned = append(pruned, ip)
		}
		_, err = tx.Exec("DELETE FROM scans WHERE id NOT IN (SELECT DISTINCT scan_id FROM scan_pcs)")
		return err
	})
	if err != nil {
		return nil, err
	}
	return pruned, nil
}

// markLatestNotConnected marks the latest payload unreachable without
// touching scan times.
func markLatestNotConnected(tx *sql.Tx, ip string) error {
	scanID, payload, found, err := latestScanPCForIP(tx, ip)
	if err != nil || !found {
		return err
	}
	_, hasError := payload["connection_error"]
	if !pyval.Truthy(get(payload, "reachable", true)) && !hasError {
		return nil
	}
	payload["reachable"] = false
	delete(payload, "connection_error")
	payloadJSON, err := encodePayload(payload)
	if err != nil {
		return err
	}
	_, err = tx.Exec("UPDATE scan_pcs SET payload_json = ? WHERE scan_id = ? AND ip = ?", payloadJSON, scanID, ip)
	return err
}
