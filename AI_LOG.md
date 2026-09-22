# AI Traceability & Development Log

- **Developer:** Venkata Ravi Kumar Rongali
- **Primary AI Tools Used:** Claude Code (VS Code Extension)

## Prompt Log

### Entry 1 — 2026-09-21 18:37 CDT

- **Prompt Summary:** Requested `main.py` for the audit log service's core FastAPI layer, built on `database.py`/`crypto_utils.py`: Pydantic schemas (`AuditEventCreate`, `AuditEventResponse`, `PaginatedResponse`); `POST /audit/events` with server-assigned UTC timestamp, UUIDv4 id, and hash-chain linkage; `GET /audit/events` with filters and Base64 `(timestamp,id)` cursor pagination (`limit+1` fetch trick for `has_more`, no `update`/`delete` routes); `GET /audit/verify` to walk the chain and report `INTACT`/`BROKEN` with the first violation.
- **Generated Output (high level):** Since `database.py` and `crypto_utils.py` did not yet exist, Claude authored all three files: `crypto_utils.py` (canonical-JSON payload hashing, chained SHA-256 record hashing), `database.py` (SQLite schema/indexes, `init_db`, `get_latest_record_hash`, append-only `insert_audit_event`, filtered/paginated `query_events`, `get_all_events_ordered`), and `main.py` (the three endpoints above, wired to a FastAPI `lifespan` startup hook that calls `init_db()`). Added a `.gitignore` for the runtime SQLite file and `__pycache__`.
- **My Engineering Action:** Reviewed the generated hash-chaining logic (payload hash vs. record hash composition, `GENESIS` sentinel for the first record) for correctness against the append-only/tamper-evidence requirement. Had Claude install `fastapi`/`uvicorn` locally and smoke-test the running service: created multiple chained events, confirmed cursor pagination correctly continues across pages, and directly edited a payload in the SQLite file to confirm `GET /audit/verify` detects it as a `HASH_MISMATCH` on the correct record. Confirmed no update/delete endpoints were exposed, satisfying the append-only constraint.

### Entry 2 — 2026-09-21 18:52 CDT

- **Prompt Summary:** Enforce `payload` as a JSON object (not plain text); add connection timeout + WAL mode to `get_connection()`; index `(timestamp DESC, id DESC)` to match query sort order.
- **Generated Output:** `payload JSON NOT NULL CHECK (json_valid(payload) AND json_type(payload)='object')`; `get_connection(timeout=30.0)` with `PRAGMA journal_mode=WAL`; index rebuilt as `(timestamp DESC, id DESC)`.
- **My Engineering Action:** Verified WAL mode activates and index DDL matches via a scratch DB, then re-ran the live server smoke test to confirm inserts/verify still pass. Added `.gitignore` entries for the new `-wal`/`-shm` files.

### Entry 3 — 2026-09-21 19:05 CDT

- **Prompt Summary:** Re-confirm `main.py` implements Scenario A (`POST/GET /audit/events`, `GET /audit/verify`) with Pydantic models for all requests/responses, including chain-verification status.
- **Generated Output:** Existing endpoints already matched; added the one missing piece — `ChainViolation`/`ChainVerificationResponse` Pydantic models, with `/audit/verify` now typed via `response_model` instead of returning a raw dict.
- **My Engineering Action:** Confirmed via the running app's OpenAPI schema that all four models are registered, and re-hit `/audit/verify` to confirm the typed response still surfaces tampered records correctly.

### Entry 4 — 2026-09-21 (test suite)

- **Prompt Summary:** Create a comprehensive pytest suite (`test_main.py`) for `crypto_utils.py`, `database.py`, and `main.py`, using an isolated test database and FastAPI's `TestClient`.
- **Generated Output:** `test_main.py` with an autouse fixture that monkeypatches `database.DB_PATH` to a per-test temp file; unit tests for hashing and persistence; API tests for create/list/verify covering filters, pagination, validation, and tamper detection (both `HASH_MISMATCH` and `CHAIN_DISCONTINUITY`).
- **My Engineering Action:** Ran the suite (`pytest -q`) and confirmed 57/57 passing; installed `httpx2`/`pytest` locally since `TestClient` needed them.

### Entry 5 — 2026-09-21 (same-second ordering bug)

- **Prompt Summary:** Flagged a chain-verification ordering issue when multiple events occur within the same second.
- **Generated Output:** Root cause: `id` (a random UUID) was used to break timestamp ties in `get_latest_record_hash`, `query_events`, and `get_all_events_ordered`, which has no relation to true insertion order and could falsely report `CHAIN_DISCONTINUITY`. Fixed by tiebreaking on SQLite's implicit `rowid` (monotonic, append-only table) everywhere, including the pagination cursor (`timestamp,rowid` instead of `timestamp,id`).
- **My Engineering Action:** Proved the bug and the fix empirically -- temporarily reverted the ordering to `id`-based, confirmed 3 new regression tests failed with the exact reported symptom (false `CHAIN_DISCONTINUITY` on a valid same-second chain), then restored the fix and confirmed all 61 tests pass.

### Entry 6 — 2026-09-21 (architecture doc)

- **Prompt Summary:** Create `ARCHITECTURE.md` with a clean, high-level system architecture and data-flow diagram using Mermaid.
- **Generated Output:** `ARCHITECTURE.md` with a component diagram, write/read/verify sequence diagrams, a hash-chain diagram, and notes on WAL concurrency and the `rowid` ordering fix.
- **My Engineering Action:** Rendered every Mermaid block through `@mermaid-js/mermaid-cli` to catch syntax errors before committing; one sequence diagram used an unsupported literal `\n`/backtick in a message and was corrected after the render failed.

