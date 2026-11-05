// Package store is the web panel's SQLite persistence (panel.db): the
// tracked-PC registry (scan_store.py), per-day usage snapshots
// (snapshot_store.py) and reverse-agent heartbeats (agent_sync_store.py),
// over the schema in panel_db.py.
//
// It reads and writes the same panel.db as the Python panel, with the same
// schema, SQL, timestamp strings and JSON payloads, so either panel can take
// over the other's database. The Python implementation is the reference:
// testdata/panelstore/vectors.json is generated from it
// (tests/panelstore_vectors_gen.py) and vectors_test.go replays every
// scenario, checking query results and table contents after each step.
//
// # Values and time
//
// PC-info payloads are dynamically typed dicts (see package pyval). Times are
// stored as Python isoformat(timespec="seconds") strings with the local UTC
// offset; a stored time without an offset is taken to be local, as Python's
// astimezone() does. Store.Now and Store.Loc stand in for panel_clock.
//
// # Known differences from the Python implementation
//
//   - JSON payloads are written with sorted keys instead of insertion order.
//   - Hostname de-duplication on the dashboard lower-cases with
//     strings.ToLower rather than str.casefold (they differ only for a few
//     non-ASCII letters such as ß).
//   - Each operation runs in one transaction (BEGIN IMMEDIATE), where Python
//     reads before its implicit write transaction starts.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no cgo)

	"kidpcmonitor/panel/pyval"
	"kidpcmonitor/secrets"
)

// DBFilename is panel_db.DB_FILENAME.
const DBFilename = "panel.db"

// DefaultPath is config_dir()/panel.db.
func DefaultPath() string { return filepath.Join(secrets.ConfigDir(), DBFilename) }

// Info is a PC-info payload.
type Info = map[string]any

// Store is an open panel.db.
type Store struct {
	db *sql.DB

	// Now returns the current time (default time.Now) and Loc is the local
	// timezone (default time.Local); tests and vectors pin both.
	Now func() time.Time
	Loc *time.Location
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS snapshots (
    username TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (username, hostname, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_hostname ON snapshots(hostname);
CREATE INDEX IF NOT EXISTS idx_snapshots_username ON snapshots(username);
CREATE INDEX IF NOT EXISTS idx_snapshots_ip ON snapshots(ip);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    network_label TEXT NOT NULL,
    subnet TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS scan_pcs (
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, ip),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS panel_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reverse_agents (
    hostname TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reverse_agents_ip ON reverse_agents(ip);
`

// Open opens (creating if needed) the database at path, switches it to WAL
// and brings the schema up to date, as panel_db.connect does the first time.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Python's sqlite3 leaves foreign keys off; so do we. _txlock=immediate
	// makes every transaction take the write lock up front.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(0)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db, Now: time.Now, Loc: time.Local}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	// Switching a new file to WAL needs no other connection open, so do it on
	// the pool's first connection before anything else runs.
	if _, err := s.db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("enable WAL: %w", err)
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(schemaSQL); err != nil {
			return err
		}
		if err := ensureScanPCsHostname(tx); err != nil {
			return err
		}
		_, err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_scan_pcs_hostname ON scan_pcs(hostname COLLATE NOCASE)")
		return err
	})
}

func ensureScanPCsHostname(tx *sql.Tx) error {
	rows, err := tx.Query("PRAGMA table_info(scan_pcs)")
	if err != nil {
		return err
	}
	hasHostname := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "hostname" {
			hasHostname = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasHostname {
		if _, err := tx.Exec("ALTER TABLE scan_pcs ADD COLUMN hostname TEXT"); err != nil {
			return err
		}
	}
	return backfillScanPCsHostname(tx)
}

func backfillScanPCsHostname(tx *sql.Tx) error {
	type pending struct {
		rowid    int64
		hostname string
	}
	rows, err := tx.Query("SELECT rowid, payload_json FROM scan_pcs WHERE hostname IS NULL OR hostname = ''")
	if err != nil {
		return err
	}
	var updates []pending
	for rows.Next() {
		var rowid int64
		var raw string
		if err := rows.Scan(&rowid, &raw); err != nil {
			rows.Close()
			return err
		}
		payload, err := decodePayload(raw)
		if err != nil {
			continue
		}
		if h, ok := payload["hostname"].(string); ok && h != "" {
			updates = append(updates, pending{rowid, h})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range updates {
		if _, err := tx.Exec("UPDATE scan_pcs SET hostname = ? WHERE rowid = ?", u.hostname, u.rowid); err != nil {
			return err
		}
	}
	return nil
}

// tx runs fn in one transaction, committing when it returns nil.
func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// now is panel_clock.now(): the current time in the local timezone.
func (s *Store) now() time.Time { return s.Now().In(s.Loc) }

// stamp is now().isoformat(timespec="seconds").
func (s *Store) stamp() string { return pyval.ISOFormatSeconds(s.now(), true) }

// parseTime is datetime.fromisoformat plus panel_clock.localize for naive
// values.
func (s *Store) parseTime(value string) (time.Time, error) {
	t, aware, err := pyval.FromISOFormat(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad stored time %q: %w", value, err)
	}
	if !aware {
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), s.Loc)
	}
	return t, nil
}

// localToday is panel_clock.now().date() as midnight UTC on that date.
func (s *Store) localToday() time.Time {
	y, m, d := s.now().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

var errNotObject = errors.New("payload is not a JSON object")

func decodePayload(raw string) (Info, error) {
	v, err := pyval.DecodeJSON([]byte(raw))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errNotObject
	}
	return m, nil
}

func encodePayload(info Info) (string, error) { return pyval.EncodeJSON(info) }

// merge is {**base, **extra}.
func merge(base Info, extra Info) Info {
	out := make(Info, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// textValue is the str a Python value becomes when bound to a TEXT column.
func textValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return pyval.Str(v)
}

// get is dict.get(key, default).
func get(info Info, key string, fallback any) any {
	if v, ok := info[key]; ok {
		return v
	}
	return fallback
}

// getMeta / setMeta are panel_db.get_meta / set_meta.
func getMeta(tx *sql.Tx, key string) (string, bool, error) {
	var value string
	err := tx.QueryRow("SELECT value FROM panel_meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func setMeta(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec("INSERT OR REPLACE INTO panel_meta (key, value) VALUES (?, ?)", key, value)
	return err
}
