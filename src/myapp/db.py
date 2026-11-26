"""Save analysis history in a SQLite database."""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    total_events INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    alert_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id INTEGER NOT NULL REFERENCES uploads(id),
    kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


def connect(path: Path) -> sqlite3.Connection:
    """Open the database (creating the file and tables if needed)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_upload(conn: sqlite3.Connection, name: str, report: dict[str, Any]) -> int:
    """Store one analysis and its alerts. Returns the new upload id.

    Values always go in through ? placeholders, never by pasting text into
    the SQL. That is what prevents SQL injection.
    """
    with conn:  # one transaction: both inserts succeed or neither does
        cursor = conn.execute(
            "INSERT INTO uploads"
            " (name, uploaded_at, total_events, failed, alert_count)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                name[:100],
                datetime.now().isoformat(timespec="seconds"),
                report["total_events"],
                report["failed"],
                len(report["alerts"]),
            ),
        )
        upload_id = cursor.lastrowid
        if upload_id is None:
            raise RuntimeError("could not save upload")
        conn.executemany(
            "INSERT INTO alerts (upload_id, kind, ip, detail) VALUES (?, ?, ?, ?)",
            [(upload_id, a["kind"], a["ip"], a["detail"]) for a in report["alerts"]],
        )
    return upload_id


def list_uploads(conn: sqlite3.Connection, limit: int = 10) -> list[dict[str, Any]]:
    """The most recent uploads, newest first."""
    rows = conn.execute(
        "SELECT id, name, uploaded_at, total_events, failed, alert_count"
        " FROM uploads ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    return [dict(row) for row in rows]


def get_alerts(conn: sqlite3.Connection, upload_id: int) -> list[dict[str, Any]]:
    """The alerts saved for one upload."""
    rows = conn.execute(
        "SELECT kind, ip, detail FROM alerts WHERE upload_id = ? ORDER BY id",
        (upload_id,),
    )
    return [dict(row) for row in rows]


def repeat_offenders(
    conn: sqlite3.Connection, min_uploads: int = 2
) -> list[dict[str, Any]]:
    """IP addresses that triggered alerts in at least min_uploads different uploads."""
    rows = conn.execute(
        "SELECT ip, COUNT(DISTINCT upload_id) AS uploads, COUNT(*) AS alerts"
        " FROM alerts GROUP BY ip"
        " HAVING COUNT(DISTINCT upload_id) >= ?"
        " ORDER BY uploads DESC, alerts DESC, ip",
        (min_uploads,),
    )
    return [dict(row) for row in rows]
