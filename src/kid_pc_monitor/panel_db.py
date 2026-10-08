"""Shared SQLite connection and schema for the web panel."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Literal

from kid_pc_monitor.paths import config_dir

DB_FILENAME = "panel.db"

_db_path_override: Path | None = None

# Switching a new database file to WAL fails at once with "database is locked"
# when another connection is open (SQLite skips the busy timeout to avoid a
# deadlock), so the one-time setup runs under a lock, once per path.
_initialized_paths: set[Path] = set()
_init_lock = threading.Lock()


def db_path() -> Path:
    if _db_path_override is not None:
        return _db_path_override
    return config_dir() / DB_FILENAME


class PanelConnection(sqlite3.Connection):
    """SQLite connection that closes when its context manager exits.

    ``sqlite3.Connection`` commits or rolls back on ``__exit__`` but leaves the
    connection open. Callers use ``with connect() as conn``, so without an
    explicit close every request and prune cycle leaks a database handle until
    the process hits its open-file limit and later opens fail.
    """

    def __exit__(self, exc_type, exc_value, traceback) -> Literal[False]:
        try:
            super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()
        return False


def connect() -> PanelConnection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, factory=PanelConnection)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        with _init_lock:
            if path not in _initialized_paths:
                conn.execute("PRAGMA journal_mode=WAL")
                ensure_schema(conn)
                conn.commit()
                _initialized_paths.add(path)
    except BaseException:
        conn.close()
        raise
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
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
        """
    )
    _ensure_scan_pcs_hostname(conn)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_pcs_hostname ON scan_pcs(hostname COLLATE NOCASE)"
    )


def _ensure_scan_pcs_hostname(conn: sqlite3.Connection) -> None:
    columns = {
        row["name"] if isinstance(row, sqlite3.Row) else row[1]
        for row in conn.execute("PRAGMA table_info(scan_pcs)").fetchall()
    }
    if "hostname" not in columns:
        conn.execute("ALTER TABLE scan_pcs ADD COLUMN hostname TEXT")
    _backfill_scan_pcs_hostname(conn)


def _backfill_scan_pcs_hostname(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT rowid, payload_json
        FROM scan_pcs
        WHERE hostname IS NULL OR hostname = ''
        """
    ).fetchall()
    for row in rows:
        rowid = row["rowid"] if isinstance(row, sqlite3.Row) else row[0]
        payload_json = row["payload_json"] if isinstance(row, sqlite3.Row) else row[1]
        try:
            payload = json.loads(payload_json)
        except TypeError, json.JSONDecodeError:
            continue
        hostname = payload.get("hostname")
        if isinstance(hostname, str) and hostname:
            conn.execute(
                "UPDATE scan_pcs SET hostname = ? WHERE rowid = ?",
                (hostname, rowid),
            )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM panel_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO panel_meta (key, value) VALUES (?, ?)",
        (key, value),
    )
