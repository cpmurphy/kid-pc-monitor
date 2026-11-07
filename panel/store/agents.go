package store

import (
	"database/sql"
	"errors"
	"time"
)

// RecentAgentSeconds is how long a reverse heartbeat counts as recent
// (agent_sync_store.RECENT_AGENT_SECONDS).
const RecentAgentSeconds = 180

// RecordAgentPoll records the latest status a reverse-connected agent
// reported (agent_sync_store.record_agent_poll).
func (s *Store) RecordAgentPoll(hostname, ip string, info Info) error {
	payload := merge(info, Info{"hostname": hostname, "ip": ip, "reachable": true})
	payloadJSON, err := encodePayload(payload)
	if err != nil {
		return err
	}
	_, err = s.exec(`INSERT OR REPLACE INTO reverse_agents
            (hostname, ip, last_seen, payload_json)
        VALUES (?, ?, ?, ?)`, hostname, ip, s.stamp(), payloadJSON)
	return err
}

// ClearAgentForIP drops the heartbeat rows for ip.
func (s *Store) ClearAgentForIP(ip string) error {
	_, err := s.exec("DELETE FROM reverse_agents WHERE ip = ?", ip)
	return err
}

// ClearAgentForHostname drops the heartbeat row for hostname.
func (s *Store) ClearAgentForHostname(hostname string) error {
	_, err := s.exec("DELETE FROM reverse_agents WHERE hostname = ?", hostname)
	return err
}

// RecentAgentForIP returns the newest heartbeat from ip if it is younger
// than maxAge (0 means RecentAgentSeconds), else nil.
func (s *Store) RecentAgentForIP(ip string, maxAge time.Duration) (Info, error) {
	return s.recentAgent(`SELECT hostname, ip, last_seen, payload_json
        FROM reverse_agents
        WHERE ip = ?
        ORDER BY last_seen DESC
        LIMIT 1`, ip, maxAge)
}

// RecentAgentForHostname returns hostname's heartbeat if it is younger than
// maxAge (0 means RecentAgentSeconds), else nil.
func (s *Store) RecentAgentForHostname(hostname string, maxAge time.Duration) (Info, error) {
	return s.recentAgent(`SELECT hostname, ip, last_seen, payload_json
        FROM reverse_agents
        WHERE hostname = ?`, hostname, maxAge)
}

func (s *Store) recentAgent(query, param string, maxAge time.Duration) (Info, error) {
	if maxAge == 0 {
		maxAge = RecentAgentSeconds * time.Second
	}
	// agent_sync_store._now() drops microseconds.
	now := s.now().Truncate(time.Second)
	cutoff := now.Add(-maxAge)
	var hostname, ip, lastSeen, raw string
	err := s.db.QueryRow(query, param).Scan(&hostname, &ip, &lastSeen, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastSeen == "" {
		return nil, nil
	}
	seen, err := s.parseTime(lastSeen)
	if err != nil {
		return nil, err
	}
	if seen.Before(cutoff) {
		return nil, nil
	}
	payload, err := decodePayload(raw)
	if err != nil {
		return nil, err
	}
	payload["hostname"] = hostname
	payload["ip"] = ip
	payload["last_seen"] = lastSeen
	return payload, nil
}
