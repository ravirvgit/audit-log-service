"""FastAPI application exposing the append-only audit log API.

Endpoints:
    POST /audit/events  -- append a new event to the log (Write API)
    GET  /audit/events  -- paginated, filterable read access (Query API)
    GET  /audit/verify  -- walk the hash chain and confirm it is untampered

There is deliberately no update or delete endpoint. Every stored record
is chained to its predecessor via `prev_hash`/`record_hash`
(see crypto_utils.py), so mutating or removing a past record would
either have to be invisible to `GET /audit/verify` or would break the
chain for it -- either way, the safest and simplest guarantee is to not
expose a way to do it at all.
"""

import base64
import binascii
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from crypto_utils import compute_payload_hash, compute_record_hash
from database import (
    GENESIS_HASH,
    get_all_events_ordered,
    get_latest_record_hash,
    init_db,
    insert_audit_event,
    query_events,
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AuditEventCreate(BaseModel):
    """Fields a client supplies when appending a new audit event.

    Everything else (`id`, `timestamp`, `prev_hash`, `record_hash`) is
    assigned by the server so that a client cannot forge ordering,
    timing, or the integrity chain.
    """

    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: Dict[str, Any]


class AuditEventResponse(BaseModel):
    """A fully-formed, stored audit record, as returned by the API."""

    id: str
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: Dict[str, Any]
    timestamp: str
    prev_hash: str
    record_hash: str


class PaginatedResponse(BaseModel):
    """A single page of audit events plus a cursor for fetching the next page."""

    items: List[AuditEventResponse]
    next_cursor: Optional[str] = None
    has_more: bool


class ChainViolation(BaseModel):
    """Details of the first place the hash chain fails to verify."""

    record_id: str
    expected_hash: str
    actual_hash: str
    violation_type: str


class ChainVerificationResponse(BaseModel):
    """Result of walking the audit log's hash chain end to end."""

    status: str
    total_records: Optional[int] = None
    first_violation: Optional[ChainViolation] = None


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the SQLite schema once on application startup."""
    init_db()
    yield


app = FastAPI(title="Audit Log Service", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_response(row: Any) -> AuditEventResponse:
    """Convert a sqlite3.Row from audit_events into an AuditEventResponse."""
    return AuditEventResponse(
        id=row["id"],
        event_type=row["event_type"],
        actor_id=row["actor_id"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        payload=json.loads(row["payload"]),
        timestamp=row["timestamp"],
        prev_hash=row["prev_hash"],
        record_hash=row["record_hash"],
    )


def _encode_cursor(timestamp: str, seq: int) -> str:
    """Encode a (timestamp, rowid) pagination position as an opaque Base64 string.

    `rowid` (SQLite's true insertion-order counter), not the public
    `id`, is used to break ties between events sharing the same
    timestamp -- `id` is a random UUID with no relationship to
    insertion order.
    """
    raw = f"{timestamp},{seq}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> Tuple[str, int]:
    """Decode a cursor produced by `_encode_cursor`, rejecting malformed input."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        timestamp, seq_str = raw.split(",", 1)
        seq = int(seq_str)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    return timestamp, seq


# ---------------------------------------------------------------------------
# Write API
# ---------------------------------------------------------------------------


@app.post("/audit/events", response_model=AuditEventResponse, status_code=201)
def create_audit_event(event: AuditEventCreate) -> AuditEventResponse:
    """Append a new event to the audit log.

    The timestamp is assigned here, by the server, in UTC ISO-8601
    (`YYYY-MM-DDTHH:MM:SSZ`) -- a client-supplied timestamp would let a
    caller manipulate ordering or backdate an event. The new record's
    `record_hash` is derived from the current chain tip
    (`get_latest_record_hash`), so every event is cryptographically
    linked to the one before it.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prev_hash = get_latest_record_hash()
    record_id = str(uuid.uuid4())

    payload_hash = compute_payload_hash(event.payload)
    record_hash = compute_record_hash(
        prev_hash,
        record_id,
        event.event_type,
        event.actor_id,
        event.resource_type,
        event.resource_id,
        payload_hash,
        timestamp,
    )

    record = {
        "id": record_id,
        "event_type": event.event_type,
        "actor_id": event.actor_id,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "payload": event.payload,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }
    insert_audit_event(record)
    return AuditEventResponse(**record)


# ---------------------------------------------------------------------------
# Query API
# ---------------------------------------------------------------------------


@app.get("/audit/events", response_model=PaginatedResponse)
def list_audit_events(
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    event_type: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse:
    """List audit events newest-first, with optional filters and cursor pagination.

    `cursor` is the Base64-encoded `timestamp,rowid` of the last item on
    the previous page; results are filtered to `(timestamp, rowid) <
    (cursor_ts, cursor_seq)`. `rowid` (SQLite's true insertion-order
    counter), not the public `id`, breaks ties between events sharing a
    timestamp, since `id` is a random UUID unrelated to insertion order.
    Internally this fetches `limit + 1` rows so `has_more` can be
    determined from the extra row alone, without a second `COUNT(*)`
    query.
    """
    cursor_ts: Optional[str] = None
    cursor_seq: Optional[int] = None
    if cursor is not None:
        cursor_ts, cursor_seq = _decode_cursor(cursor)

    rows = query_events(
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        event_type=event_type,
        from_ts=from_ts,
        to_ts=to_ts,
        cursor_ts=cursor_ts,
        cursor_seq=cursor_seq,
        limit=limit + 1,
    )

    has_more = len(rows) > limit
    page_rows = rows[:limit]
    items = [_row_to_response(row) for row in page_rows]

    next_cursor: Optional[str] = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = _encode_cursor(last["timestamp"], last["rowid"])

    return PaginatedResponse(items=items, next_cursor=next_cursor, has_more=has_more)


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


@app.get("/audit/verify", response_model=ChainVerificationResponse)
def verify_chain() -> ChainVerificationResponse:
    """Walk the entire audit log and confirm the hash chain is untampered.

    For each record, in `(timestamp ASC, id ASC)` order, this:
    1. Recomputes `record_hash` from the record's own stored fields and
       compares it to the stored value (catches a field edited in place).
    2. Confirms the record's stored `prev_hash` equals the previous
       record's actual `record_hash` (or `GENESIS` for the first
       record) (catches an inserted, deleted, or reordered record).

    Returns the first violation found, if any; an empty log is
    trivially INTACT with `total_records: 0`.
    """
    records = get_all_events_ordered()
    prev_expected = GENESIS_HASH

    for record in records:
        payload_hash = compute_payload_hash(json.loads(record["payload"]))
        recomputed_hash = compute_record_hash(
            record["prev_hash"],
            record["id"],
            record["event_type"],
            record["actor_id"],
            record["resource_type"],
            record["resource_id"],
            payload_hash,
            record["timestamp"],
        )

        if recomputed_hash != record["record_hash"]:
            return ChainVerificationResponse(
                status="BROKEN",
                first_violation=ChainViolation(
                    record_id=record["id"],
                    expected_hash=recomputed_hash,
                    actual_hash=record["record_hash"],
                    violation_type="HASH_MISMATCH",
                ),
            )

        if record["prev_hash"] != prev_expected:
            return ChainVerificationResponse(
                status="BROKEN",
                first_violation=ChainViolation(
                    record_id=record["id"],
                    expected_hash=prev_expected,
                    actual_hash=record["prev_hash"],
                    violation_type="CHAIN_DISCONTINUITY",
                ),
            )

        prev_expected = record["record_hash"]

    return ChainVerificationResponse(status="INTACT", total_records=len(records))
