# Audit Log Service

An append-only, cryptographically tamper-evident audit log built with
FastAPI and SQLite. Every event is chained to the one before it with a
SHA-256 hash, so any edit, deletion, or reordering of history is detectable
(`GET /audit/verify`). Built in three stages:

- **Scenario A** -- the core append-only log.
- **Scenario B** -- redaction, retention, and export on top of it.
- **Scenario C** -- a compliance-access report built on the Scenario B export engine.

For the system design, see [ARCHITECTURE.md](ARCHITECTURE.md). For the
redaction/retention cryptographic strategy, see
[REDACTION_DESIGN.md](REDACTION_DESIGN.md). For how the Scenario C ask was
disambiguated, see
[SCENARIO_C_COMPLIANCE_REPORTING.md](SCENARIO_C_COMPLIANCE_REPORTING.md).
For the AI-assisted development trail, see [AI_LOG.md](AI_LOG.md).

## Step-by-step execution instructions for evaluators

**Prerequisites:** Python 3.10+ and `pip`. SQLite itself needs no separate
install -- it's in the Python standard library.

### 1. Clone and enter the repository

```bash
git clone <this-repository-url>
cd audit-log-service
```

### 2. Install dependencies

```bash
pip install fastapi uvicorn pytest httpx2
```

### 3. Run the application

```bash
uvicorn main:app --reload
```

- Interactive API docs (try every endpoint from the browser): `http://127.0.0.1:8000/docs`.
- The database schema is created automatically on startup via a FastAPI
  `lifespan` hook that calls `init_db()` -- there is no separate migration
  step to run first.
- `audit_log.db` (plus its `-wal`/`-shm` WAL journal sidecar files) is
  created automatically on first run, in the working directory. These
  files are listed in `.gitignore` and never committed; delete them at any
  time for a completely clean database.

### 4. Sample walkthrough, scenario by scenario

All commands below assume the server from step 3 is running on
`127.0.0.1:8000`. Run them in order -- later ones reuse the `id` returned
by the first `POST`.

**Scenario A -- insert, list, verify**

```bash
# Insert an event
curl -X POST http://127.0.0.1:8000/audit/events \
  -H "Content-Type: application/json" \
  -d '{"event_type":"ACCOUNT_READ","actor_id":"analyst1","resource_type":"BANK_ACCOUNT","resource_id":"acct-42","payload":{"field":"balance"}}'
# -> 201, note the "id" in the response for the next steps

# List events for that account
curl "http://127.0.0.1:8000/audit/events?resource_id=acct-42&limit=20"

# Verify the whole chain is untampered
curl http://127.0.0.1:8000/audit/verify
# -> {"status":"INTACT","total_records":1,"first_violation":null}
```

**Scenario B -- redact, archive, export**

```bash
# Redact one field on the event created above (replace <id> with the real id)
curl -X POST http://127.0.0.1:8000/audit/events/<id>/redact \
  -H "Content-Type: application/json" \
  -d '{"fields":["field"]}'
# -> payload_hash/record_hash are unchanged; payload now shows "[REDACTED]"

# Archive anything older than 90 days (soft flag, nothing is deleted)
curl -X POST "http://127.0.0.1:8000/audit/retention/apply?days=90"

# Export a self-contained, offline-verifiable bundle for this account
curl "http://127.0.0.1:8000/audit/export?resource_id=acct-42"
```

**Scenario C -- compliance access report**

```bash
curl "http://127.0.0.1:8000/audit/reports/compliance-access?resource_id=acct-42&from_ts=2020-01-01T00:00:00Z&to_ts=2030-01-01T00:00:00Z"
# -> unique_actors, access_frequency_by_event_type, the full event list,
#    and a verification_proof (bounding hashes + whole-log chain_status)
```

The four requirements-clarification assumptions behind this endpoint
(access scope, target granularity, output format, and query-performance
SLA) are recapped in
["Scenario C assumptions" below](#scenario-c-assumptions-recap) and
covered in full in
[SCENARIO_C_COMPLIANCE_REPORTING.md](SCENARIO_C_COMPLIANCE_REPORTING.md).

### 5. Stop the server

`Ctrl+C` in the terminal running `uvicorn`. `audit_log.db` and its `-wal`/
`-shm` files remain on disk (gitignored) for inspection afterward; delete
them at any time to start from a clean slate on the next run.

### 6. Run the automated test suite

```bash
pytest -v
```

93 tests -- a mix of pure unit tests (`TestCryptoUtils`, `TestCursorHelpers`),
direct database-layer tests (`TestDatabase`), and integration tests that
exercise the real FastAPI app end-to-end through `TestClient` against a
real (temp-file) SQLite database (every other class). Isolation comes from
an autouse `pytest` fixture that points `database.DB_PATH` at a fresh temp
file per test and calls `init_db()`, so test runs never read or write the
database the running service in step 3 uses. See "Testing approach" below
for exactly what's covered per scenario.

## Scenario breakdown

### Scenario A -- Core Log Engine

- `POST /audit/events` -- append an event. The server assigns the `id`
  (UUIDv4) and `timestamp` (UTC, `YYYY-MM-DDTHH:MM:SSZ`) -- never the
  client -- and computes `payload_hash`/`record_hash`, chaining the new
  record to the current chain tip.
- `GET /audit/events` -- filter by `actor_id`, `resource_type`,
  `resource_id`, `event_type`, `from_ts`/`to_ts`, with keyset (cursor)
  pagination.
- `GET /audit/verify` -- walk the whole chain and report `INTACT` or
  `BROKEN` with the first violation (`HASH_MISMATCH` or
  `CHAIN_DISCONTINUITY`).

There is deliberately no update or delete endpoint. Details, diagrams, and
the schema in [ARCHITECTURE.md](ARCHITECTURE.md).

### Scenario B -- Redaction, Retention & Export

- `POST /audit/events/{record_id}/redact` -- blank out specific payload
  fields with `"[REDACTED]"`, without invalidating `record_hash`.
- `POST /audit/retention/apply` -- soft-archive events older than N days
  (`is_archived`/`archived_at`); nothing is ever deleted.
- `GET /audit/export` -- a self-contained, offline-verifiable JSON bundle
  of matching events plus a cryptographic bounding proof.

The cryptographic mechanism that makes redaction possible without breaking
the chain -- persisting `payload_hash` as its own column, independent of
the live `payload` -- is explained in
[REDACTION_DESIGN.md](REDACTION_DESIGN.md).

### Scenario C -- Compliance Access Reporting

- `GET /audit/reports/compliance-access` -- for one client account
  (`resource_id`) over a `[from_ts, to_ts]` window, reports every
  `ACCOUNT_READ`/`RECORD_UPDATED`/`DATA_EXPORT` event: unique actors,
  per-event-type frequency, the full chronological event list, and a
  `verification_proof` (bounding hashes + whole-log chain status) reusing
  the Scenario B export engine.

How the original ambiguous ask ("regulators need to audit access to client
account data") was decomposed into this concrete design, and what was
explicitly scoped out, is in
[SCENARIO_C_COMPLIANCE_REPORTING.md](SCENARIO_C_COMPLIANCE_REPORTING.md).

#### Scenario C assumptions (recap)

The original ask was under-specified along four axes; each was resolved
with an explicit assumption rather than guessed silently (full analysis,
including which of these were already supported by the existing system and
which exposed real gaps, is in
[SCENARIO_C_COMPLIANCE_REPORTING.md](SCENARIO_C_COMPLIANCE_REPORTING.md)):

| # | Question | Assumption |
| --- | --- | --- |
| 1. Access scope | Does "access" mean reads, mutations, failed auth attempts, or admin exports? | Audit `ACCOUNT_READ`, `RECORD_UPDATED`, and `DATA_EXPORT` events; exclude background health-checks |
| 2. Target granularity | What identifies "a client account"? | A single `resource_id`, scoped to account-shaped `resource_type`s |
| 3. Output format | Raw dumps, PDFs, or verifiable bundles? | An aggregated JSON report backed by the Scenario B export engine's cryptographic bounding proof |
| 4. Query performance | Real-time or async? What time window? | Synchronous response, filterable `[from_ts, to_ts]` window, backed by a composite `(resource_type, resource_id)` index |

## Final engineering summary

**Rationale.** A hash chain (the same idea behind git or a blockchain) was
chosen over, say, database-level audit triggers or a write-once filesystem
because it's verifiable independent of the storage engine: `GET
/audit/verify` proves the log's integrity from the data alone, without
trusting SQLite's own guarantees. SQLite in WAL mode was chosen over a
client-server database for this assignment's scope -- zero external
infrastructure, and WAL mode still gives non-blocking concurrent reads
against the single writer. FastAPI + Pydantic gives typed request/response
contracts and free OpenAPI docs with very little code.

**System artifacts:**

| File | Role |
| --- | --- |
| `main.py` | FastAPI routes, Pydantic schemas, the startup `lifespan` hook |
| `database.py` | The only code that touches SQLite -- schema, indexes, queries |
| `crypto_utils.py` | Pure hashing functions, no I/O |
| `test_main.py` | 93 pytest cases across unit, database, and API layers |
| `ARCHITECTURE.md` | System design, diagrams, schema, indexing rationale |
| `REDACTION_DESIGN.md` | Scenario B's cryptographic strategy and trade-offs |
| `SCENARIO_C_COMPLIANCE_REPORTING.md` | Scenario C's ambiguity decomposition and scope boundary |
| `AI_LOG.md` | Chronological AI-assisted development log |
| `ATTESTATION.md` | Submission attestation |

**Security risks (see also the "Fit against the current system" sections
of the Scenario docs):**

- **No authentication or authorization exists anywhere in this codebase.**
  Every endpoint, including the compliance-access report and the export
  bundle, is open to any caller. This is the single largest gap for any
  real deployment, and is called out explicitly rather than implied away.
- A hash chain proves *internal consistency*, not immunity to an attacker
  with direct write access to the SQLite file -- such an attacker could
  regenerate an entirely different but internally self-consistent chain
  from scratch. There is no external anchor (signature, WORM storage, or
  out-of-band timestamping of the chain tip). See "What no hash-chain-only
  design can prove" in [REDACTION_DESIGN.md](REDACTION_DESIGN.md).
- Once a record is archived (`is_archived = 1`), even without being
  redacted, `GET /audit/verify` stops independently checking its live
  payload against its stored hash. This was a deliberate, explicit design
  choice (see `REDACTION_DESIGN.md`'s threat model section), not an
  oversight -- but it is a real reduction in tamper-evidence for archived
  records.
- No request size limits, no rate limiting.

**Architectural trade-offs:**

- SQLite/WAL over a client-server database: simpler for this scope, at the
  cost of single-writer throughput and no built-in replication.
- `rowid` (SQLite's implicit, strictly-increasing insertion counter) is
  used to break same-timestamp ties, instead of the public `id` (a random
  UUID unrelated to insertion order) -- this was a real bug found and
  fixed mid-project (see `AI_LOG.md` Entry 5).
- `payload_hash` is persisted as its own column, separate from
  `record_hash`, specifically so Scenario B's redaction could exist
  without a cascading rehash of the entire downstream chain.
- Verification trusts the stored `payload_hash` instead of a live
  recompute whenever `is_redacted` *or* `is_archived` is set -- a broader
  exemption than redaction alone strictly requires, kept for consistency
  with how retention was specified.

**Key assumptions:**

- Single-process deployment; SQLite's WAL mode is not a substitute for a
  multi-node database.
- Timestamps are UTC, second-granularity ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`).
- `payload` must be a JSON object (enforced by a `CHECK` constraint); no
  nested-field redaction, only top-level keys.
- Scenario C's access event types (`ACCOUNT_READ`, `RECORD_UPDATED`,
  `DATA_EXPORT`) are a fixed allow-list, not client-configurable -- see
  [SCENARIO_C_COMPLIANCE_REPORTING.md](SCENARIO_C_COMPLIANCE_REPORTING.md)
  for why.
- **Authentication/authorization was scoped out for this submission due to
  time constraints, not because it was judged unnecessary.** A JWT-based
  scheme (e.g. validating a bearer token per request, scoping regulator
  access to specific `resource_type`s via claims) is the natural next
  addition and would sit cleanly in front of the existing routes as
  FastAPI dependencies -- it was left out here to keep the submission
  focused on the audit-log/redaction/compliance logic itself.
- **Project structure is intentionally a single flat folder**
  (`main.py`, `database.py`, `crypto_utils.py`, `test_main.py` side by
  side), which fits a project this size in Python but would not be how a
  larger, production system should be organized. A real deployment would
  split this into packages (e.g. `app/routers/`, `app/models/`,
  `app/services/`, `app/db/`, `tests/`), add a dependency-injected
  settings/config module instead of a module-level `DB_PATH` constant, and
  likely move off a single SQLite file entirely (see "Architectural
  trade-offs" above).

**Current limitations:**

- No auth/authz (see Security risks and "Key assumptions" above).
- `GET /audit/reports/compliance-access` returns its entire matching set
  in one response -- no pagination, so a very active account over a wide
  window could return a large payload.
- The Scenario C 2-second SLA for a 365-day window is a design target, not
  a load-tested guarantee.
- Retention (`POST /audit/retention/apply`) runs synchronously in the
  request; there is no background job model.
- Schema evolution is `CREATE TABLE IF NOT EXISTS` only -- there is no
  migration framework for changing an existing table's columns.
- Flat single-folder project layout (see "Key assumptions" above) --
  fine at this scale, not how it should look in production.

## Testing approach

93 automated `pytest` cases, isolated per test via a fresh temp-file
SQLite database (an autouse fixture swaps `database.DB_PATH` before each
test and calls `init_db()`). Both unit tests (pure functions, no I/O) and
integration tests (the real FastAPI app driven through `TestClient` against
a real, if temporary, SQLite database) are included -- there is no mocking
of the database or the hashing functions anywhere in the suite.

**By scenario:**

- **Scenario A** (`TestCryptoUtils`, `TestDatabase`, `TestCreateAuditEvent`,
  `TestListAuditEvents`, `TestVerifyChain`, `TestCursorHelpers`) -- hashing
  correctness, schema/constraints, the write/query/verify API contracts,
  pagination, and both tamper-detection paths (`HASH_MISMATCH`,
  `CHAIN_DISCONTINUITY`), including the same-timestamp ordering regression.
- **Scenario B** (`TestRedactAuditEvent`, `TestRetentionApply`,
  `TestExportAuditEvents`) -- redaction preserves the chain, retention
  archives without deleting, export's bounding proof and whole-log status.
- **Scenario C** (`TestComplianceAccessReport`) -- the fixed event-type
  allow-list, time-window filtering, actor/frequency summaries, and that
  its chain status reflects the whole log, not just the reported account.

**By test class:**

| Test class | Count | Covers |
| --- | --- | --- |
| `TestCryptoUtils` | 14 | Unit tests for `compute_payload_hash`/`compute_record_hash`: determinism, key-order independence, SHA-256 hex format, and that changing any single hash input changes the output |
| `TestDatabase` | 11 | Schema/index creation, WAL mode, the `payload` `CHECK` constraint (invalid JSON and non-object JSON both rejected), filtering, keyset pagination, and `rowid`-based ordering |
| `TestCreateAuditEvent` | 14 | Write-path API contract: server-assigned id/timestamp, chain linkage, cross-checking `record_hash` against an independent recomputation, validation errors, no update/delete routes |
| `TestListAuditEvents` | 12 | Filters, full pagination walk with no gaps/duplicates, invalid cursor handling, limit bounds |
| `TestVerifyChain` | 6 | `INTACT`/`BROKEN` reporting, `HASH_MISMATCH` vs. `CHAIN_DISCONTINUITY` detection, first-violation-only reporting |
| `TestRedactAuditEvent` | 7 | Field redaction, `payload_hash`/`record_hash` preservation, 404 on unknown id, chain stays `INTACT` after redaction |
| `TestRetentionApply` | 5 | Archiving by cutoff, idempotency, and the documented trade-off that archived records' payload tampering is no longer caught |
| `TestExportAuditEvents` | 8 | Filtering, bounding-hash correctness, whole-log chain status independent of the exported subset |
| `TestComplianceAccessReport` | 12 | Event-type allow-list, time-window filtering, unique-actor dedup, per-event-type frequency (including explicit zero-counts), chronological ordering, bounding proof |
| `TestCursorHelpers` | 4 | Cursor encode/decode round-trip and malformed-input rejection |

Negative and tamper-detection cases specifically include: `HASH_MISMATCH`
from a directly-edited payload, `CHAIN_DISCONTINUITY` from a forged
`prev_hash`, same-second event ordering (a real regression test -- see
`AI_LOG.md` Entry 5), invalid Base64 cursors, malformed/non-object JSON
payloads, and 404/422 responses for missing records and invalid input.
