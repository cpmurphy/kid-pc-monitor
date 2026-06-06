"""Shared SQLite connection and schema for the web panel."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from kid_pc_monitor.paths import config_dir

DB_FILENAME = "panel.db"

_db_path_override: Path | None = None


def db_path() -> Path:
    if _db_path_override is not None:
        return _db_path_override
    return config_dir() / DB_FILENAME


def connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    ensure_schema(conn)
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
        except (TypeError, json.JSONDecodeError):
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
