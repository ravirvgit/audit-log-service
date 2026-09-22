"""FastAPI application exposing the append-only audit log API.

Scenario A -- the core log:
    POST /audit/events  -- append a new event to the log (Write API)
    GET  /audit/events  -- paginated, filterable read access (Query API)
    GET  /audit/verify  -- walk the hash chain and confirm it is untampered

Scenario B -- redaction, retention, and export on top of that log:
    POST /audit/events/{record_id}/redact -- blank out specific payload fields
    POST /audit/retention/apply           -- archive events older than N days
    GET  /audit/export                    -- a self-contained, verifiable export

Scenario C -- a compliance-facing report built on the Scenario B export engine:
    GET  /audit/reports/compliance-access -- access history for one client account

There is deliberately no *delete* endpoint, and no generic update
endpoint. Every stored record is chained to its predecessor via
`prev_hash`/`record_hash` (see crypto_utils.py), so mutating or
removing a past record would either have to be invisible to
`GET /audit/verify` or would break the chain for it. Redaction is the
one narrow, deliberate exception: it overwrites specific payload
fields in place, but leaves `payload_hash`/`record_hash` untouched, so
the chain still verifies (see `database.redact_event_payload`).
"""

import base64
import binascii
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from crypto_utils import compute_payload_hash, compute_record_hash
from database import (
    GENESIS_HASH,
    archive_events_older_than,
    export_events_by_target,
    get_all_events_ordered,
    get_latest_record_hash,
    init_db,
    insert_audit_event,
    query_events,
    redact_event_payload,
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
    payload_hash: str
    timestamp: str
    prev_hash: str
    record_hash: str
    is_redacted: bool
    is_archived: bool
    archived_at: Optional[str] = None


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


class RedactRequest(BaseModel):
    """Top-level payload field names to blank out on one event."""

    fields: List[str] = Field(..., min_length=1)


class RedactResponse(BaseModel):
    """The event as it stands immediately after redaction."""

    id: str
    payload: Dict[str, Any]
    payload_hash: str
    record_hash: str
    is_redacted: bool


class RetentionApplyResponse(BaseModel):
    """Result of applying the retention policy once."""

    cutoff_days: int
    cutoff_timestamp: str
    archived_at: str
    archived_count: int


class ExportRecordProof(BaseModel):
    """One exported record's own chain linkage, for offline verification."""

    id: str
    prev_hash: str
    record_hash: str
    payload_hash: str


class ExportMetadata(BaseModel):
    """Facts about the export operation itself."""

    exported_at: str
    record_count: int
    chain_verification_status: str


class VerificationProof(BaseModel):
    """Everything a recipient needs to verify the exported records offline.

    `bounding_start_hash`/`bounding_end_hash` are the entry and exit
    points of this (possibly filtered) subset within the *overall*
    chain -- the exported record set's own `prev_hash`/`record_hash`
    values may reference records that are not themselves part of the
    export, so these two hashes are what anchor the subset to the full
    log without requiring every record in between.
    """

    genesis_hash: str
    bounding_start_hash: Optional[str] = None
    bounding_end_hash: Optional[str] = None
    records: List[ExportRecordProof]


class ExportBundle(BaseModel):
    """A self-contained, verifiable export of a subset of the audit log."""

    records: List[AuditEventResponse]
    export_metadata: ExportMetadata
    verification_proof: VerificationProof


class ComplianceVerificationProof(BaseModel):
    """Cryptographic proof that the report reflects an untampered log."""

    bounding_start_hash: Optional[str] = None
    bounding_end_hash: Optional[str] = None
    chain_status: str


class ComplianceAccessReport(BaseModel):
    """A regulator/compliance-facing report of access to one client account."""

    resource_id: str
    from_ts: str
    to_ts: str
    event_count: int
    unique_actor_count: int
    unique_actors: List[str]
    access_frequency_by_event_type: Dict[str, int]
    events: List[AuditEventResponse]
    verification_proof: ComplianceVerificationProof


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
        payload_hash=row["payload_hash"],
        timestamp=row["timestamp"],
        prev_hash=row["prev_hash"],
        record_hash=row["record_hash"],
        is_redacted=bool(row["is_redacted"]),
        is_archived=bool(row["is_archived"]),
        archived_at=row["archived_at"],
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
        "payload_hash": payload_hash,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }
    insert_audit_event(record)
    return AuditEventResponse(**record, is_redacted=False, is_archived=False, archived_at=None)


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


def _run_chain_verification(records: List[Any]) -> ChainVerificationResponse:
    """Walk a sequence of records, oldest first, and confirm the hash chain is untampered.

    Shared by `GET /audit/verify` (the whole log) and `GET /audit/export`
    (a full-log check reported alongside a filtered export). For each
    record, this:

    1. Recomputes `record_hash` from the record's own stored fields and
       compares it to the stored value (catches a field edited in
       place). For a record with `is_redacted` or `is_archived` set,
       the stored `payload_hash` is used as-is instead of being
       recomputed from the current payload -- redaction deliberately
       changes the payload without changing this original commitment
       (see crypto_utils.py), so recomputing it live would falsely
       flag every redacted or archived record as tampered.
    2. Confirms the record's stored `prev_hash` equals the previous
       record's actual `record_hash` (or `GENESIS` for the first
       record) (catches an inserted, deleted, or reordered record).

    Returns the first violation found, if any; an empty sequence is
    trivially INTACT with `total_records: 0`.
    """
    prev_expected = GENESIS_HASH

    for record in records:
        if record["is_redacted"] or record["is_archived"]:
            payload_hash = record["payload_hash"]
        else:
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


@app.get("/audit/verify", response_model=ChainVerificationResponse)
def verify_chain() -> ChainVerificationResponse:
    """Walk the entire audit log and confirm the hash chain is untampered."""
    return _run_chain_verification(get_all_events_ordered())


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


@app.post("/audit/events/{record_id}/redact", response_model=RedactResponse)
def redact_audit_event(record_id: str, request: RedactRequest) -> RedactResponse:
    """Blank out specific top-level payload fields on an existing event.

    This is the one deliberate exception to "append-only, no in-place
    edits": `database.redact_event_payload` overwrites the listed
    fields with `"[REDACTED]"` but leaves `payload_hash` and
    `record_hash` untouched, so `GET /audit/verify` keeps validating
    the chain afterward. Field names not present in the payload are
    silently ignored.
    """
    row = redact_event_payload(record_id, request.fields)
    if row is None:
        raise HTTPException(status_code=404, detail="Audit event not found")

    return RedactResponse(
        id=row["id"],
        payload=json.loads(row["payload"]),
        payload_hash=row["payload_hash"],
        record_hash=row["record_hash"],
        is_redacted=bool(row["is_redacted"]),
    )


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


@app.post("/audit/retention/apply", response_model=RetentionApplyResponse)
def apply_retention_policy(days: int = Query(..., ge=0)) -> RetentionApplyResponse:
    """Archive every event older than `days` days.

    Archiving sets `is_archived`/`archived_at` only -- it is a soft
    flag, not a delete. Archived records remain fully queryable via
    `GET /audit/events` and verifiable via `GET /audit/verify`,
    preserving the append-only guarantee.
    """
    result = archive_events_older_than(days)
    return RetentionApplyResponse(
        cutoff_days=days,
        cutoff_timestamp=result["cutoff_timestamp"],
        archived_at=result["archived_at"],
        archived_count=result["archived_count"],
    )


# ---------------------------------------------------------------------------
# Bulk verifiable export
# ---------------------------------------------------------------------------


@app.get("/audit/export", response_model=ExportBundle)
def export_audit_events(
    actor_id: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> ExportBundle:
    """Export a self-contained, offline-verifiable bundle of matching events.

    `records` is every event matching `actor_id`/`resource_id` (both
    optional; omitting both exports the whole log), oldest first.
    `export_metadata.chain_verification_status` reports the *entire*
    log's chain health at export time -- not just this subset -- so a
    recipient knows the audit trail this export was drawn from was
    intact when it was produced. `verification_proof` gives the
    recipient enough to independently recompute each exported record's
    own `record_hash` from its `payload_hash` and other fields, plus
    the hashes bounding this subset within the full chain, without
    needing every record in between.
    """
    export = export_events_by_target(actor_id=actor_id, resource_id=resource_id)
    rows = export["records"]

    chain_status = _run_chain_verification(get_all_events_ordered())

    return ExportBundle(
        records=[_row_to_response(row) for row in rows],
        export_metadata=ExportMetadata(
            exported_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            record_count=len(rows),
            chain_verification_status=chain_status.status,
        ),
        verification_proof=VerificationProof(
            genesis_hash=GENESIS_HASH,
            bounding_start_hash=export["bounding_start_hash"],
            bounding_end_hash=export["bounding_end_hash"],
            records=[
                ExportRecordProof(
                    id=row["id"],
                    prev_hash=row["prev_hash"],
                    record_hash=row["record_hash"],
                    payload_hash=row["payload_hash"],
                )
                for row in rows
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Scenario C: compliance reporting
# ---------------------------------------------------------------------------

#: The fixed set of event types a compliance-access report covers. This is
#: not client-configurable -- it is what "access" was scoped to mean for
#: this report (see SCENARIO_C_COMPLIANCE_REPORTING.md).
COMPLIANCE_ACCESS_EVENT_TYPES = ["ACCOUNT_READ", "RECORD_UPDATED", "DATA_EXPORT"]


@app.get("/audit/reports/compliance-access", response_model=ComplianceAccessReport)
def compliance_access_report(
    resource_id: str,
    from_ts: str,
    to_ts: str,
) -> ComplianceAccessReport:
    """Report every access event for one client account within a UTC time window.

    Covers `ACCOUNT_READ`, `RECORD_UPDATED`, and `DATA_EXPORT` events on
    `resource_id`, between `from_ts` and `to_ts` inclusive. Built on the
    same `export_events_by_target` engine as `GET /audit/export`
    (Scenario B), so the `verification_proof` carries the same
    `bounding_start_hash`/`bounding_end_hash` guarantee: `chain_status`
    reports the *entire* log's chain health at request time, not just
    this account's events, so a regulator knows the underlying audit
    trail this report was drawn from was untampered.
    """
    export = export_events_by_target(
        resource_id=resource_id,
        event_types=COMPLIANCE_ACCESS_EVENT_TYPES,
        from_ts=from_ts,
        to_ts=to_ts,
    )
    rows = export["records"]

    unique_actors = sorted({row["actor_id"] for row in rows})
    frequency = {event_type: 0 for event_type in COMPLIANCE_ACCESS_EVENT_TYPES}
    for row in rows:
        frequency[row["event_type"]] += 1

    chain_status = _run_chain_verification(get_all_events_ordered())

    return ComplianceAccessReport(
        resource_id=resource_id,
        from_ts=from_ts,
        to_ts=to_ts,
        event_count=len(rows),
        unique_actor_count=len(unique_actors),
        unique_actors=unique_actors,
        access_frequency_by_event_type=frequency,
        events=[_row_to_response(row) for row in rows],
        verification_proof=ComplianceVerificationProof(
            bounding_start_hash=export["bounding_start_hash"],
            bounding_end_hash=export["bounding_end_hash"],
            chain_status=chain_status.status,
        ),
    )
