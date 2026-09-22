"""SQLite persistence layer for the append-only audit log.

There is intentionally no `update_event` or `delete_event` function --
the audit trail is append-only, so the only write path exposed is
`insert_audit_event`.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional

DB_PATH = "audit_log.db"
GENESIS_HASH = "GENESIS"


def get_connection(timeout: float = 30.0) -> sqlite3.Connection:
    """Open a new SQLite connection with row access by column name.

    WAL mode lets the FastAPI process's concurrent readers and its
    single writer proceed without blocking each other; `timeout`
    bounds how long a connection waits on a lock (e.g. the brief write
    lock held during an INSERT) before raising
    `sqlite3.OperationalError`, instead of failing immediately.
    """
    conn = sqlite3.connect(DB_PATH, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create the audit_events table and its indexes if they do not already exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload JSON NOT NULL CHECK (json_valid(payload) AND json_type(payload) = 'object'),
                timestamp TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            )
            """
        )
        # Every ordered query below breaks timestamp ties with `rowid`
        # (SQLite's implicit true insertion-order counter -- this table's
        # PRIMARY KEY is TEXT, so it does not alias rowid away), rather
        # than the public `id`, a random UUID unrelated to insertion
        # order. SQLite does not allow `rowid` inside a CREATE INDEX
        # column list -- it is implicitly appended to every index on a
        # rowid table already -- so indexing `timestamp` alone still
        # lets the DESC/ASC scans above resolve correctly.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_ts_id ON audit_events (timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_resource "
            "ON audit_events (resource_type, resource_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type)"
        )
        conn.commit()


def get_latest_record_hash() -> str:
    """Return the record_hash of the most recently appended event.

    Ties on `timestamp` (multiple events in the same second) are broken
    by `rowid`, the true insertion-order counter, rather than `id` --
    a random UUID has no relationship to insertion order and would
    occasionally pick the wrong "latest" record. Returns the sentinel
    `GENESIS_HASH` when the log is empty, which is what the first-ever
    record's `prev_hash` must equal.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT record_hash FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return row["record_hash"] if row is not None else GENESIS_HASH


def insert_audit_event(record: Dict[str, Any]) -> None:
    """Append one fully-formed audit record. This is the only write path into the table."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_events
                (id, event_type, actor_id, resource_type, resource_id,
                 payload, timestamp, prev_hash, record_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["id"],
                record["event_type"],
                record["actor_id"],
                record["resource_type"],
                record["resource_id"],
                json.dumps(record["payload"], sort_keys=True, separators=(",", ":"), default=str),
                record["timestamp"],
                record["prev_hash"],
                record["record_hash"],
            ),
        )
        conn.commit()


def query_events(
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    event_type: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    cursor_ts: Optional[str] = None,
    cursor_seq: Optional[int] = None,
    limit: int = 20,
) -> List[sqlite3.Row]:
    """Return up to `limit` events, newest first, matching the given filters.

    Pagination is keyset-based: when `cursor_ts`/`cursor_seq` are given,
    only rows with `(timestamp, rowid) < (cursor_ts, cursor_seq)` are
    returned. `rowid` (not the public `id`, a random UUID) breaks
    timestamp ties in true insertion order. Callers pass `limit + 1` so
    they can tell whether another page exists without a separate
    `COUNT(*)` query.
    """
    clauses: List[str] = []
    params: List[Any] = []

    if actor_id is not None:
        clauses.append("actor_id = ?")
        params.append(actor_id)
    if resource_type is not None:
        clauses.append("resource_type = ?")
        params.append(resource_type)
    if resource_id is not None:
        clauses.append("resource_id = ?")
        params.append(resource_id)
    if event_type is not None:
        clauses.append("event_type = ?")
        params.append(event_type)
    if from_ts is not None:
        clauses.append("timestamp >= ?")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append("timestamp <= ?")
        params.append(to_ts)
    if cursor_ts is not None and cursor_seq is not None:
        clauses.append("(timestamp, rowid) < (?, ?)")
        params.append(cursor_ts)
        params.append(cursor_seq)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT *, rowid FROM audit_events
        {where_sql}
        ORDER BY timestamp DESC, rowid DESC
        LIMIT ?
    """
    params.append(limit)

    with get_connection() as conn:
        return conn.execute(sql, params).fetchall()


def get_all_events_ordered() -> List[sqlite3.Row]:
    """Return every event ordered by (timestamp ASC, rowid ASC), for full chain verification.

    `rowid` breaks timestamp ties in true insertion order, so records
    created within the same second are still verified in the order
    their hash chain was actually built in.
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT *, rowid FROM audit_events ORDER BY timestamp ASC, rowid ASC"
        ).fetchall()
