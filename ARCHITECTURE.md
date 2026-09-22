# Architecture

## Overview

The audit log service is a small FastAPI application backed by a single SQLite
file. It exposes three endpoints -- append an event, query events, and verify
the log's integrity -- and is deliberately **append-only**: there is no
update or delete endpoint anywhere in the API surface.

Every event is cryptographically chained to the one before it (a hash chain,
the same idea behind a blockchain or a git commit history), so any edit,
deletion, or reordering of a past record is detectable by walking the chain
and recomputing hashes.

## Components

```mermaid
flowchart TB
    Client["Client\n(any HTTP caller)"]

    subgraph App["FastAPI application (main.py)"]
        direction TB
        Write["POST /audit/events\nWrite API"]
        Query["GET /audit/events\nQuery API"]
        Verify["GET /audit/verify\nChain Verification"]
    end

    Crypto["crypto_utils.py\ncompute_payload_hash\ncompute_record_hash"]
    DB["database.py\ninit_db / get_latest_record_hash\ninsert_audit_event / query_events\nget_all_events_ordered"]
    SQLite[("audit_log.db\n(SQLite, WAL mode)\naudit_events table")]

    Client -->|JSON request| Write
    Client -->|filters + cursor| Query
    Client -->|GET| Verify

    Write --> Crypto
    Write --> DB
    Query --> DB
    Verify --> Crypto
    Verify --> DB

    DB --> SQLite

    Write -->|201 Created\nAuditEventResponse| Client
    Query -->|200 OK\nPaginatedResponse| Client
    Verify -->|200 OK\nChainVerificationResponse| Client
```

- **main.py** -- FastAPI routes, Pydantic request/response schemas, and the
  `lifespan` hook that calls `init_db()` on startup.
- **crypto_utils.py** -- pure functions with no I/O: canonical payload
  hashing and the chained record hash.
- **database.py** -- the only code that touches SQLite. Opens a fresh
  connection per call (WAL journal mode, bounded lock `timeout`), and is the
  sole place that knows the table schema and SQL.
- **audit_log.db** -- a single SQLite file, one table (`audit_events`), with
  a `CHECK` constraint enforcing that `payload` is a valid JSON object.

## Write path: `POST /audit/events`

```mermaid
sequenceDiagram
    participant C as Client
    participant API as main.py
    participant DB as database.py
    participant Crypto as crypto_utils.py
    participant SQL as SQLite

    C->>API: POST /audit/events {event_type, actor_id, resource_type, resource_id, payload}
    API->>API: assign UTC ISO-8601 timestamp + UUIDv4 id
    API->>DB: get_latest_record_hash()
    DB->>SQL: SELECT record_hash ORDER BY timestamp DESC, rowid DESC LIMIT 1
    SQL-->>DB: latest record_hash (or none)
    DB-->>API: prev_hash ("GENESIS" if log is empty)
    API->>Crypto: compute_payload_hash(payload)
    Crypto-->>API: payload_hash
    API->>Crypto: compute_record_hash(prev_hash, id, ..., payload_hash, timestamp)
    Crypto-->>API: record_hash
    API->>DB: insert_audit_event(record)
    DB->>SQL: INSERT INTO audit_events (...)
    SQL-->>DB: OK
    API-->>C: 201 Created, AuditEventResponse
```

The server -- never the client -- assigns the `id` and `timestamp`, which is
what prevents a caller from manipulating ordering or backdating an event.
`rowid` (SQLite's implicit, strictly-increasing insertion counter) breaks
ties between events that land in the same second; the public `id` is a
random UUID and is unsuitable for that, since it carries no ordering
information.

## Hash chain

```mermaid
flowchart LR
    G["GENESIS"] --> E1
    subgraph E1["Event 1"]
        direction TB
        E1F["prev_hash = GENESIS\nfields + payload_hash\n→ record_hash = H1"]
    end
    E1 -->|H1| E2
    subgraph E2["Event 2"]
        direction TB
        E2F["prev_hash = H1\nfields + payload_hash\n→ record_hash = H2"]
    end
    E2 -->|H2| E3
    subgraph E3["Event 3"]
        direction TB
        E3F["prev_hash = H2\nfields + payload_hash\n→ record_hash = H3"]
    end
```

Each `record_hash` is a SHA-256 digest over `prev_hash` plus every immutable
field of the record. Changing any field of any past record -- or deleting or
reordering one -- changes that record's hash and breaks the link the next
record depends on.

## Read path: `GET /audit/events`

```mermaid
sequenceDiagram
    participant C as Client
    participant API as main.py
    participant DB as database.py
    participant SQL as SQLite

    C->>API: GET /audit/events?actor_id=...&cursor=...&limit=20
    API->>API: decode cursor -> (timestamp, rowid) or none
    API->>DB: query_events(filters..., cursor, limit + 1)
    DB->>SQL: SELECT ... WHERE filters AND (timestamp, rowid) < cursor ORDER BY timestamp DESC, rowid DESC LIMIT (limit+1)
    SQL-->>DB: up to limit+1 rows
    DB-->>API: rows
    API->>API: has_more = len(rows) > limit, trim to limit
    API->>API: encode next_cursor from last row's (timestamp, rowid)
    API-->>C: 200 OK, PaginatedResponse{items, next_cursor, has_more}
```

Fetching `limit + 1` rows lets the API decide `has_more` from the extra row
alone, avoiding a second `COUNT(*)` query.

## Verification path: `GET /audit/verify`

```mermaid
flowchart TD
    Start["Fetch all records\nORDER BY timestamp ASC, rowid ASC"] --> Loop{"For each record,\noldest to newest"}
    Loop --> Recompute["Recompute record_hash\nfrom the record's own stored fields"]
    Recompute --> HashCheck{"recomputed_hash ==\nstored record_hash?"}
    HashCheck -->|No| HashBroken["BROKEN\nviolation_type = HASH_MISMATCH"]
    HashCheck -->|Yes| ChainCheck{"stored prev_hash ==\nprevious record's record_hash?\n(GENESIS for the first record)"}
    ChainCheck -->|No| ChainBroken["BROKEN\nviolation_type = CHAIN_DISCONTINUITY"]
    ChainCheck -->|Yes| Advance["prev_expected = this record_hash"]
    Advance --> Loop
    Loop -->|no more records| Intact["INTACT\ntotal_records = N"]
```

`HASH_MISMATCH` catches a record whose own fields were edited in place;
`CHAIN_DISCONTINUITY` catches a record that was inserted, deleted, or
reordered relative to its neighbors. The endpoint returns the first
violation found and stops there.

## Concurrency and storage

- SQLite runs in **WAL (write-ahead log)** mode, so concurrent readers
  (`GET /audit/events`, `GET /audit/verify`) do not block the single writer
  (`POST /audit/events`), and vice versa.
- Every connection opens with a `timeout`, so a request waiting on a lock
  fails with a clear error instead of hanging indefinitely.
- The table's real primary key for ordering purposes is SQLite's implicit
  `rowid`, not the public `id` (a random UUID) -- see `database.py` for why
  this matters once multiple events share the same one-second timestamp.

## Scenario B: Redaction, Retention, and Export

Building on the append-only log above, three more endpoints let a record's
payload be redacted, older records be archived, and a subset of the log be
exported for offline verification -- without ever deleting a row or
breaking the hash chain. The full cryptographic reasoning and threat model
are in [REDACTION_DESIGN.md](REDACTION_DESIGN.md); this section covers the
request flow for each endpoint.

### Schema additions

| Column | Purpose |
| --- | --- |
| `payload_hash` | The original payload's hash, persisted at ingestion time rather than only ever existing inside `record_hash`. Redaction preserves this value, which is what keeps `record_hash` -- and the chain -- valid afterward. |
| `is_redacted` | Set once any field on this record has been redacted. |
| `is_archived` | Set once this record has been archived by the retention policy. |
| `archived_at` | UTC timestamp of when archiving happened (`NULL` until then). |

### Redaction: `POST /audit/events/{record_id}/redact`

```mermaid
sequenceDiagram
    participant C as Client
    participant API as main.py
    participant DB as database.py
    participant SQL as SQLite

    C->>API: POST /audit/events/{id}/redact {fields: [...]}
    API->>DB: redact_event_payload(id, fields)
    DB->>SQL: SELECT * FROM audit_events WHERE id = ?
    SQL-->>DB: current row (or none)
    DB->>DB: replace listed keys in payload with "[REDACTED]"
    DB->>SQL: UPDATE audit_events SET payload = ?, is_redacted = 1 WHERE id = ?
    Note over DB,SQL: payload_hash and record_hash are NOT part of this UPDATE
    SQL-->>DB: OK
    DB-->>API: updated row (or None if id not found)
    API-->>C: 200 OK RedactResponse, or 404 if not found
```

This is the one deliberate exception to "append-only, no in-place edits" --
see [REDACTION_DESIGN.md](REDACTION_DESIGN.md) for why leaving
`payload_hash`/`record_hash` untouched keeps the chain valid.

### Retention: `POST /audit/retention/apply`

```mermaid
sequenceDiagram
    participant C as Client
    participant API as main.py
    participant DB as database.py
    participant SQL as SQLite

    C->>API: POST /audit/retention/apply?days=90
    API->>DB: archive_events_older_than(days)
    DB->>DB: cutoff = now - days, archived_at = now
    DB->>SQL: UPDATE audit_events SET is_archived = 1, archived_at = ? WHERE timestamp < ? AND is_archived = 0
    SQL-->>DB: rows updated
    DB-->>API: cutoff_timestamp, archived_at, archived_count
    API-->>C: 200 OK RetentionApplyResponse
```

Archiving never deletes a row: archived records stay fully queryable via
`GET /audit/events` and are still walked by `GET /audit/verify`.

### Export: `GET /audit/export`

```mermaid
sequenceDiagram
    participant C as Client
    participant API as main.py
    participant DB as database.py
    participant SQL as SQLite

    C->>API: GET /audit/export?actor_id=...&resource_id=...
    API->>DB: export_events_by_target(actor_id, resource_id)
    DB->>SQL: SELECT ... WHERE filters ORDER BY timestamp ASC, rowid ASC
    SQL-->>DB: matching rows
    DB-->>API: records, bounding_start_hash, bounding_end_hash
    API->>API: run full-log chain verification (get_all_events_ordered)
    Note over API: chain status covers the WHOLE log, not just this subset
    API-->>C: 200 OK ExportBundle{records, export_metadata, verification_proof}
```

`verification_proof` carries each exported record's own
`prev_hash`/`record_hash`/`payload_hash`, plus the subset's
`bounding_start_hash`/`bounding_end_hash` -- the entry and exit points of
this (possibly filtered) subset within the larger chain -- so a recipient
can recompute and confirm each record's `record_hash` offline without
needing the rest of the log.

### Verification, refined

`GET /audit/verify`'s per-record check (see the Verification path section
above) now branches on whether a record has been redacted or archived:

```mermaid
flowchart LR
    Flag{"is_redacted or\nis_archived?"} -->|Yes| Stored["use the stored payload_hash"]
    Flag -->|No| Live["recompute payload_hash from\nthe live payload"]
```

Everything else -- the `record_hash` recomputation and the `prev_hash`
chain-linkage check -- is unchanged. See
[REDACTION_DESIGN.md](REDACTION_DESIGN.md) for exactly what this does and
does not still catch, including the one non-obvious trade-off: this same
exemption also applies to archived-but-not-redacted records, even though
archiving alone never touches the payload.
