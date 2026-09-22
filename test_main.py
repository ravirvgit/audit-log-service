"""Test suite for the audit log service.

Covers three layers:
    * crypto_utils.py -- pure hashing functions (TestCryptoUtils)
    * database.py     -- SQLite persistence (TestDatabase)
    * main.py         -- the FastAPI HTTP surface (Test*Api classes)

Every test runs against an isolated, throwaway SQLite file (see the
`isolated_db` fixture below) so nothing here ever touches the real
`audit_log.db`.
"""

import base64
import re
import uuid
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import crypto_utils
import database
import main

ISO_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Point database.py at a fresh temp-file SQLite DB for this test only.

    A temp file (rather than ":memory:") is required because
    `get_connection()` opens a brand-new connection per call -- an
    in-memory DB would reset itself on every call and never persist
    data between statements. Scoping this per test function (not per
    session) keeps each test's chain state fully isolated from the
    others.
    """
    db_file = tmp_path / "test_audit.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    database.init_db()
    yield db_file


@pytest.fixture
def client(isolated_db):
    """A TestClient wired to the isolated DB (via the startup lifespan)."""
    with TestClient(main.app) as test_client:
        yield test_client


def _build_record(
    prev_hash: str,
    timestamp: str,
    *,
    event_type: str = "TEST_EVENT",
    actor_id: str = "actor-1",
    resource_type: str = "resource",
    resource_id: str = "r-1",
    payload: Optional[Dict[str, Any]] = None,
    record_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one fully-formed, correctly-hashed record for direct DB insertion."""
    payload = {"k": "v"} if payload is None else payload
    record_id = record_id or str(uuid.uuid4())
    payload_hash = crypto_utils.compute_payload_hash(payload)
    record_hash = crypto_utils.compute_record_hash(
        prev_hash, record_id, event_type, actor_id, resource_type, resource_id, payload_hash, timestamp
    )
    return {
        "id": record_id,
        "event_type": event_type,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "payload": payload,
        "payload_hash": payload_hash,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }


def _seed_chain(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Insert a sequence of events directly, correctly chained, bypassing the API.

    Useful for tests that need deterministic timestamps/ordering rather
    than whatever the wall clock happens to produce.
    """
    prev_hash = database.get_latest_record_hash()
    inserted = []
    for event in events:
        record = _build_record(prev_hash, event["timestamp"], **{k: v for k, v in event.items() if k != "timestamp"})
        database.insert_audit_event(record)
        inserted.append(record)
        prev_hash = record["record_hash"]
    return inserted


# ---------------------------------------------------------------------------
# Unit tests: crypto_utils.py
# ---------------------------------------------------------------------------


class TestCryptoUtils:
    def test_payload_hash_is_deterministic(self):
        payload = {"b": 2, "a": 1}
        assert crypto_utils.compute_payload_hash(payload) == crypto_utils.compute_payload_hash(payload)

    def test_payload_hash_ignores_key_order(self):
        assert crypto_utils.compute_payload_hash({"a": 1, "b": 2}) == crypto_utils.compute_payload_hash(
            {"b": 2, "a": 1}
        )

    def test_payload_hash_changes_with_content(self):
        assert crypto_utils.compute_payload_hash({"a": 1}) != crypto_utils.compute_payload_hash({"a": 2})

    def test_payload_hash_is_sha256_hex(self):
        digest = crypto_utils.compute_payload_hash({"a": 1})
        assert len(digest) == 64
        assert re.fullmatch(r"[0-9a-f]{64}", digest)

    def test_record_hash_is_deterministic(self):
        args = ("GENESIS", "id-1", "LOGIN", "u1", "session", "s1", "phash", "2020-01-01T00:00:00Z")
        assert crypto_utils.compute_record_hash(*args) == crypto_utils.compute_record_hash(*args)

    @pytest.mark.parametrize("changed_index", range(8))
    def test_record_hash_changes_if_any_field_changes(self, changed_index):
        base_args = ["GENESIS", "id-1", "LOGIN", "u1", "session", "s1", "phash", "2020-01-01T00:00:00Z"]
        changed_args = list(base_args)
        changed_args[changed_index] = changed_args[changed_index] + "-tampered"

        original = crypto_utils.compute_record_hash(*base_args)
        tampered = crypto_utils.compute_record_hash(*changed_args)
        assert original != tampered

    def test_record_hash_chains_to_prev_hash(self):
        """Changing prev_hash alone (simulating a different chain position) changes the result."""
        args_a = ("GENESIS", "id-1", "LOGIN", "u1", "session", "s1", "phash", "2020-01-01T00:00:00Z")
        args_b = ("some-other-prev-hash", "id-1", "LOGIN", "u1", "session", "s1", "phash", "2020-01-01T00:00:00Z")
        assert crypto_utils.compute_record_hash(*args_a) != crypto_utils.compute_record_hash(*args_b)


# ---------------------------------------------------------------------------
# Unit tests: database.py
# ---------------------------------------------------------------------------


class TestDatabase:
    def test_init_db_creates_table_and_indexes(self, isolated_db):
        conn = database.get_connection()
        try:
            tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            indexes = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        finally:
            conn.close()

        assert "audit_events" in tables
        assert "idx_audit_events_ts_id" in indexes
        assert "idx_audit_events_actor" in indexes
        assert "idx_audit_events_resource" in indexes
        assert "idx_audit_events_event_type" in indexes

    def test_get_connection_uses_wal_journal_mode(self, isolated_db):
        conn = database.get_connection()
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        assert mode.lower() == "wal"

    def test_get_latest_record_hash_is_genesis_when_empty(self, isolated_db):
        assert database.get_latest_record_hash() == database.GENESIS_HASH

    def test_insert_and_read_back_latest_hash(self, isolated_db):
        record = _build_record(database.GENESIS_HASH, "2020-01-01T00:00:00Z")
        database.insert_audit_event(record)
        assert database.get_latest_record_hash() == record["record_hash"]

    def test_payload_check_constraint_rejects_invalid_json(self, isolated_db):
        conn = database.get_connection()
        try:
            with pytest.raises(Exception):
                conn.execute(
                    "INSERT INTO audit_events "
                    "(id, event_type, actor_id, resource_type, resource_id, payload, payload_hash, timestamp, prev_hash, record_hash) "
                    "VALUES (?, 'X', 'a', 'r', 'r1', 'not-json', 'ph', '2020-01-01T00:00:00Z', 'GENESIS', 'h')",
                    (str(uuid.uuid4()),),
                )
            conn.rollback()
        finally:
            conn.close()

    def test_payload_check_constraint_rejects_non_object_json(self, isolated_db):
        """A JSON array or scalar is valid JSON but not the required object shape."""
        conn = database.get_connection()
        try:
            with pytest.raises(Exception):
                conn.execute(
                    "INSERT INTO audit_events "
                    "(id, event_type, actor_id, resource_type, resource_id, payload, payload_hash, timestamp, prev_hash, record_hash) "
                    "VALUES (?, 'X', 'a', 'r', 'r1', '[1,2,3]', 'ph', '2020-01-01T00:00:00Z', 'GENESIS', 'h')",
                    (str(uuid.uuid4()),),
                )
            conn.rollback()
        finally:
            conn.close()

    def test_query_events_filters_by_actor_id(self, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z", "actor_id": "alice"},
                {"timestamp": "2020-01-01T00:00:01Z", "actor_id": "bob"},
            ]
        )
        rows = database.query_events(actor_id="alice", limit=10)
        assert len(rows) == 1
        assert rows[0]["actor_id"] == "alice"

    def test_query_events_orders_newest_first(self, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-01T00:00:01Z"},
                {"timestamp": "2020-01-01T00:00:02Z"},
            ]
        )
        rows = database.query_events(limit=10)
        timestamps = [row["timestamp"] for row in rows]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_query_events_cursor_excludes_up_to_and_including_cursor(self, isolated_db):
        records = _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-01T00:00:01Z"},
                {"timestamp": "2020-01-01T00:00:02Z"},
            ]
        )
        all_rows = {row["id"]: row for row in database.get_all_events_ordered()}
        middle = all_rows[records[1]["id"]]

        rows = database.query_events(cursor_ts=middle["timestamp"], cursor_seq=middle["rowid"], limit=10)
        assert len(rows) == 1
        assert rows[0]["id"] == records[0]["id"]

    def test_query_events_breaks_same_timestamp_ties_by_insertion_order_not_id(self, isolated_db):
        """Events sharing a timestamp must sort by true insertion order (rowid),
        not by the random UUID `id` -- otherwise pagination/verify could
        silently reorder a validly-chained sequence of same-second events.
        """
        records = _seed_chain([{"timestamp": "2020-01-01T00:00:00Z"} for _ in range(5)])
        rows = database.query_events(limit=10)
        assert [row["id"] for row in rows] == [r["id"] for r in reversed(records)]

    def test_get_all_events_ordered_is_ascending(self, isolated_db):
        records = _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-01T00:00:01Z"},
                {"timestamp": "2020-01-01T00:00:02Z"},
            ]
        )
        rows = database.get_all_events_ordered()
        assert [row["id"] for row in rows] == [r["id"] for r in records]


# ---------------------------------------------------------------------------
# API integration tests: POST /audit/events
# ---------------------------------------------------------------------------


class TestCreateAuditEvent:
    def _payload(self, **overrides):
        body = {
            "event_type": "LOGIN",
            "actor_id": "u1",
            "resource_type": "session",
            "resource_id": "s1",
            "payload": {"ip": "1.2.3.4"},
        }
        body.update(overrides)
        return body

    def test_create_returns_201_with_full_record(self, client):
        resp = client.post("/audit/events", json=self._payload())
        assert resp.status_code == 201
        data = resp.json()
        for field in ("id", "event_type", "actor_id", "resource_type", "resource_id", "payload", "timestamp", "prev_hash", "record_hash"):
            assert field in data

    def test_create_assigns_valid_uuid4_id(self, client):
        data = client.post("/audit/events", json=self._payload()).json()
        assert uuid.UUID(data["id"]).version == 4

    def test_create_assigns_iso_utc_timestamp(self, client):
        data = client.post("/audit/events", json=self._payload()).json()
        assert ISO_TIMESTAMP_RE.match(data["timestamp"])

    def test_create_ignores_client_supplied_timestamp_and_id(self, client):
        """The server must assign id/timestamp itself -- a client can't forge either."""
        forged = self._payload()
        forged["timestamp"] = "1999-01-01T00:00:00Z"
        forged["id"] = "not-a-real-id"
        data = client.post("/audit/events", json=forged).json()
        assert data["timestamp"] != "1999-01-01T00:00:00Z"
        assert data["id"] != "not-a-real-id"
        assert ISO_TIMESTAMP_RE.match(data["timestamp"])

    def test_first_event_chains_to_genesis(self, client):
        data = client.post("/audit/events", json=self._payload()).json()
        assert data["prev_hash"] == database.GENESIS_HASH

    def test_second_event_chains_to_first(self, client):
        first = client.post("/audit/events", json=self._payload()).json()
        second = client.post("/audit/events", json=self._payload(event_type="LOGOUT")).json()
        assert second["prev_hash"] == first["record_hash"]

    def test_record_hash_matches_independent_recomputation(self, client):
        data = client.post("/audit/events", json=self._payload()).json()
        expected_payload_hash = crypto_utils.compute_payload_hash(data["payload"])
        expected_record_hash = crypto_utils.compute_record_hash(
            data["prev_hash"],
            data["id"],
            data["event_type"],
            data["actor_id"],
            data["resource_type"],
            data["resource_id"],
            expected_payload_hash,
            data["timestamp"],
        )
        assert data["record_hash"] == expected_record_hash

    @pytest.mark.parametrize("missing_field", ["event_type", "actor_id", "resource_type", "resource_id", "payload"])
    def test_create_rejects_missing_required_field(self, client, missing_field):
        body = self._payload()
        del body[missing_field]
        resp = client.post("/audit/events", json=body)
        assert resp.status_code == 422

    def test_create_rejects_non_object_payload(self, client):
        body = self._payload(payload="not-an-object")
        resp = client.post("/audit/events", json=body)
        assert resp.status_code == 422

    def test_no_update_or_delete_routes_exist(self, client):
        assert client.put("/audit/events", json=self._payload()).status_code == 405
        assert client.delete("/audit/events").status_code == 405
        assert client.patch("/audit/events", json={}).status_code == 405


# ---------------------------------------------------------------------------
# API integration tests: GET /audit/events
# ---------------------------------------------------------------------------


class TestListAuditEvents:
    def test_empty_log_returns_empty_page(self, client):
        resp = client.get("/audit/events")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"items": [], "next_cursor": None, "has_more": False}

    def test_filters_by_actor_id(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z", "actor_id": "alice"},
                {"timestamp": "2020-01-01T00:00:01Z", "actor_id": "bob"},
            ]
        )
        body = client.get("/audit/events", params={"actor_id": "alice"}).json()
        assert len(body["items"]) == 1
        assert body["items"][0]["actor_id"] == "alice"

    def test_filters_by_resource_type_and_id(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z", "resource_type": "doc", "resource_id": "d1"},
                {"timestamp": "2020-01-01T00:00:01Z", "resource_type": "doc", "resource_id": "d2"},
            ]
        )
        body = client.get("/audit/events", params={"resource_type": "doc", "resource_id": "d1"}).json()
        assert len(body["items"]) == 1
        assert body["items"][0]["resource_id"] == "d1"

    def test_filters_by_event_type(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z", "event_type": "LOGIN"},
                {"timestamp": "2020-01-01T00:00:01Z", "event_type": "LOGOUT"},
            ]
        )
        body = client.get("/audit/events", params={"event_type": "LOGOUT"}).json()
        assert len(body["items"]) == 1
        assert body["items"][0]["event_type"] == "LOGOUT"

    def test_filters_by_from_ts_and_to_ts(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-02T00:00:00Z"},
                {"timestamp": "2020-01-03T00:00:00Z"},
            ]
        )
        body = client.get(
            "/audit/events", params={"from_ts": "2020-01-02T00:00:00Z", "to_ts": "2020-01-02T23:59:59Z"}
        ).json()
        assert len(body["items"]) == 1
        assert body["items"][0]["timestamp"] == "2020-01-02T00:00:00Z"

    def test_results_are_newest_first(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-01T00:00:01Z"},
                {"timestamp": "2020-01-01T00:00:02Z"},
            ]
        )
        body = client.get("/audit/events").json()
        timestamps = [item["timestamp"] for item in body["items"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_pagination_walks_the_full_log_without_duplicates_or_gaps(self, client, isolated_db):
        seeded = _seed_chain([{"timestamp": f"2020-01-01T00:00:{i:02d}Z"} for i in range(5)])

        seen_ids: List[str] = []
        cursor = None
        pages_fetched = 0
        while True:
            params = {"limit": 2}
            if cursor:
                params["cursor"] = cursor
            body = client.get("/audit/events", params=params).json()
            seen_ids.extend(item["id"] for item in body["items"])
            pages_fetched += 1
            if not body["has_more"]:
                assert body["next_cursor"] is None
                break
            cursor = body["next_cursor"]
            assert pages_fetched <= 10  # safety net against an infinite loop bug

        assert pages_fetched == 3  # 5 items at limit=2 -> pages of 2, 2, 1
        assert seen_ids == [r["id"] for r in reversed(seeded)]

    def test_pagination_is_stable_when_events_share_the_same_timestamp(self, client, isolated_db):
        """Regression test: events landing in the same second must still
        paginate in true insertion order. The old cursor design broke ties
        on the random UUID `id`, which could reorder or duplicate/drop rows
        across pages for same-second events; `rowid` fixes this.
        """
        seeded = _seed_chain([{"timestamp": "2020-01-01T00:00:00Z"} for _ in range(5)])

        seen_ids: List[str] = []
        cursor = None
        while True:
            params = {"limit": 2}
            if cursor:
                params["cursor"] = cursor
            body = client.get("/audit/events", params=params).json()
            seen_ids.extend(item["id"] for item in body["items"])
            if not body["has_more"]:
                break
            cursor = body["next_cursor"]

        assert seen_ids == [r["id"] for r in reversed(seeded)]

    def test_invalid_cursor_returns_400(self, client):
        resp = client.get("/audit/events", params={"cursor": "%%%not-base64%%%"})
        assert resp.status_code == 400

    def test_limit_below_minimum_is_rejected(self, client):
        assert client.get("/audit/events", params={"limit": 0}).status_code == 422

    def test_limit_above_maximum_is_rejected(self, client):
        assert client.get("/audit/events", params={"limit": 101}).status_code == 422

    def test_limit_at_maximum_is_accepted(self, client):
        assert client.get("/audit/events", params={"limit": 100}).status_code == 200


# ---------------------------------------------------------------------------
# API integration tests: GET /audit/verify
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_empty_log_is_intact(self, client):
        resp = client.get("/audit/verify")
        assert resp.status_code == 200
        assert resp.json() == {"status": "INTACT", "total_records": 0, "first_violation": None}

    def test_untampered_log_is_intact(self, client):
        for i in range(3):
            client.post(
                "/audit/events",
                json={
                    "event_type": "TEST",
                    "actor_id": "u1",
                    "resource_type": "r",
                    "resource_id": str(i),
                    "payload": {"n": i},
                },
            )
        body = client.get("/audit/verify").json()
        assert body == {"status": "INTACT", "total_records": 3, "first_violation": None}

    def test_intact_when_multiple_events_share_the_same_timestamp(self, isolated_db, client):
        """Regression test: a valid chain built from same-second events must
        not be reported as BROKEN. Verify used to walk records ordered by
        (timestamp ASC, id ASC) -- since `id` is a random UUID unrelated to
        insertion order, same-second events could be visited out of the
        order their hash chain was actually built in, producing false
        CHAIN_DISCONTINUITY reports. Ordering by `rowid` instead fixes this.
        """
        _seed_chain([{"timestamp": "2020-01-01T00:00:00Z"} for _ in range(8)])
        body = client.get("/audit/verify").json()
        assert body == {"status": "INTACT", "total_records": 8, "first_violation": None}

    def test_detects_hash_mismatch_from_tampered_payload(self, client, isolated_db):
        created = client.post(
            "/audit/events",
            json={"event_type": "TEST", "actor_id": "u1", "resource_type": "r", "resource_id": "1", "payload": {"n": 1}},
        ).json()

        conn = database.get_connection()
        try:
            conn.execute("UPDATE audit_events SET payload = ? WHERE id = ?", ('{"n":999}', created["id"]))
            conn.commit()
        finally:
            conn.close()

        body = client.get("/audit/verify").json()
        assert body["status"] == "BROKEN"
        assert body["first_violation"]["violation_type"] == "HASH_MISMATCH"
        assert body["first_violation"]["record_id"] == created["id"]
        assert body["first_violation"]["actual_hash"] == created["record_hash"]

    def test_detects_chain_discontinuity_without_hash_mismatch(self, client, isolated_db):
        """Rewire record 2's prev_hash to a bogus value, keeping its own record_hash
        internally consistent, so only the chain link -- not the record's own hash --
        is broken. This isolates CHAIN_DISCONTINUITY from HASH_MISMATCH.
        """
        client.post(
            "/audit/events",
            json={"event_type": "A", "actor_id": "u1", "resource_type": "r", "resource_id": "1", "payload": {"n": 1}},
        ).json()
        second = client.post(
            "/audit/events",
            json={"event_type": "B", "actor_id": "u1", "resource_type": "r", "resource_id": "2", "payload": {"n": 2}},
        ).json()

        bogus_prev_hash = "0" * 64
        payload_hash = crypto_utils.compute_payload_hash(second["payload"])
        recomputed_hash = crypto_utils.compute_record_hash(
            bogus_prev_hash,
            second["id"],
            second["event_type"],
            second["actor_id"],
            second["resource_type"],
            second["resource_id"],
            payload_hash,
            second["timestamp"],
        )

        conn = database.get_connection()
        try:
            conn.execute(
                "UPDATE audit_events SET prev_hash = ?, record_hash = ? WHERE id = ?",
                (bogus_prev_hash, recomputed_hash, second["id"]),
            )
            conn.commit()
        finally:
            conn.close()

        body = client.get("/audit/verify").json()
        assert body["status"] == "BROKEN"
        assert body["first_violation"]["violation_type"] == "CHAIN_DISCONTINUITY"
        assert body["first_violation"]["record_id"] == second["id"]
        assert body["first_violation"]["expected_hash"] == second["prev_hash"]
        assert body["first_violation"]["actual_hash"] == bogus_prev_hash

    def test_reports_first_violation_only_when_multiple_exist(self, client, isolated_db):
        records = _seed_chain(
            [
                {"timestamp": "2020-01-01T00:00:00Z"},
                {"timestamp": "2020-01-01T00:00:01Z"},
                {"timestamp": "2020-01-01T00:00:02Z"},
            ]
        )
        conn = database.get_connection()
        try:
            # Tamper both the 2nd and 3rd records; only the 2nd (earlier, by
            # timestamp ASC) should be reported.
            conn.execute("UPDATE audit_events SET payload = '{\"tampered\":1}' WHERE id = ?", (records[1]["id"],))
            conn.execute("UPDATE audit_events SET payload = '{\"tampered\":2}' WHERE id = ?", (records[2]["id"],))
            conn.commit()
        finally:
            conn.close()

        body = client.get("/audit/verify").json()
        assert body["status"] == "BROKEN"
        assert body["first_violation"]["record_id"] == records[1]["id"]


# ---------------------------------------------------------------------------
# API integration tests: POST /audit/events/{record_id}/redact
# ---------------------------------------------------------------------------


class TestRedactAuditEvent:
    def _create(self, client, **payload_overrides):
        payload = {"account_number": "123456", "ssn": "111-22-3333", "amount": 50}
        payload.update(payload_overrides)
        return client.post(
            "/audit/events",
            json={"event_type": "PAYMENT", "actor_id": "u1", "resource_type": "txn", "resource_id": "t1", "payload": payload},
        ).json()

    def test_redact_replaces_specified_fields_with_marker(self, client):
        created = self._create(client)
        resp = client.post(f"/audit/events/{created['id']}/redact", json={"fields": ["account_number", "ssn"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["payload"]["account_number"] == "[REDACTED]"
        assert body["payload"]["ssn"] == "[REDACTED]"
        assert body["payload"]["amount"] == 50
        assert body["is_redacted"] is True

    def test_redact_preserves_payload_hash_and_record_hash(self, client):
        created = self._create(client)
        resp = client.post(f"/audit/events/{created['id']}/redact", json={"fields": ["account_number"]}).json()
        assert resp["payload_hash"] == created["payload_hash"]
        assert resp["record_hash"] == created["record_hash"]

    def test_redact_ignores_fields_not_present_in_payload(self, client):
        created = self._create(client)
        resp = client.post(
            f"/audit/events/{created['id']}/redact", json={"fields": ["not_a_real_field"]}
        ).json()
        assert resp["payload"] == created["payload"]

    def test_redact_nonexistent_record_returns_404(self, client):
        resp = client.post("/audit/events/does-not-exist/redact", json={"fields": ["ssn"]})
        assert resp.status_code == 404

    def test_redact_rejects_empty_fields_list(self, client):
        created = self._create(client)
        resp = client.post(f"/audit/events/{created['id']}/redact", json={"fields": []})
        assert resp.status_code == 422

    def test_chain_stays_intact_after_redaction(self, client):
        first = self._create(client)
        client.post(f"/audit/events/{first['id']}/redact", json={"fields": ["account_number", "ssn"]})
        # A second event chained on top of the (now redacted) first must still verify.
        client.post(
            "/audit/events",
            json={"event_type": "PAYMENT", "actor_id": "u1", "resource_type": "txn", "resource_id": "t2", "payload": {"amount": 1}},
        )
        body = client.get("/audit/verify").json()
        assert body == {"status": "INTACT", "total_records": 2, "first_violation": None}

    def test_get_events_reflects_redacted_payload_and_flag(self, client):
        created = self._create(client)
        client.post(f"/audit/events/{created['id']}/redact", json={"fields": ["ssn"]})
        body = client.get("/audit/events").json()
        assert body["items"][0]["is_redacted"] is True
        assert body["items"][0]["payload"]["ssn"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# API integration tests: POST /audit/retention/apply
# ---------------------------------------------------------------------------


class TestRetentionApply:
    def test_archives_events_older_than_cutoff(self, client, isolated_db):
        _seed_chain(
            [
                {"timestamp": "2000-01-01T00:00:00Z"},
                {"timestamp": "2099-01-01T00:00:00Z"},
            ]
        )
        body = client.post("/audit/retention/apply", params={"days": 90}).json()
        assert body["archived_count"] == 1

        events = client.get("/audit/events").json()["items"]
        archived = {item["timestamp"]: item["is_archived"] for item in events}
        assert archived["2000-01-01T00:00:00Z"] is True
        assert archived["2099-01-01T00:00:00Z"] is False

    def test_is_idempotent_on_already_archived_events(self, client, isolated_db):
        _seed_chain([{"timestamp": "2000-01-01T00:00:00Z"}])
        first = client.post("/audit/retention/apply", params={"days": 0}).json()
        second = client.post("/audit/retention/apply", params={"days": 0}).json()
        assert first["archived_count"] == 1
        assert second["archived_count"] == 0

    def test_archived_events_remain_queryable_and_chain_verifies(self, client, isolated_db):
        _seed_chain([{"timestamp": "2000-01-01T00:00:00Z"} for _ in range(3)])
        client.post("/audit/retention/apply", params={"days": 0})

        events = client.get("/audit/events").json()["items"]
        assert len(events) == 3
        assert all(item["is_archived"] for item in events)

        body = client.get("/audit/verify").json()
        assert body == {"status": "INTACT", "total_records": 3, "first_violation": None}

    def test_rejects_negative_days(self, client):
        resp = client.post("/audit/retention/apply", params={"days": -1})
        assert resp.status_code == 422

    def test_verify_does_not_detect_payload_tampering_on_archived_records(self, client, isolated_db):
        """Documents a deliberate trade-off: once a record is archived, /audit/verify
        trusts its stored payload_hash instead of recomputing from the live payload
        (same as for redacted records), so direct payload tampering on an archived
        record is no longer visible to chain verification -- only tampering with the
        chain-linkage fields (prev_hash/record_hash) still is.
        """
        # A deterministic old timestamp (rather than the live server clock) keeps
        # this test's "older than the cutoff" outcome independent of how fast the
        # test happens to run.
        seeded = _seed_chain([{"timestamp": "2000-01-01T00:00:00Z"}])
        client.post("/audit/retention/apply", params={"days": 1})

        conn = database.get_connection()
        try:
            conn.execute(
                "UPDATE audit_events SET payload = '{\"tampered\":true}' WHERE id = ?", (seeded[0]["id"],)
            )
            conn.commit()
        finally:
            conn.close()

        body = client.get("/audit/verify").json()
        assert body == {"status": "INTACT", "total_records": 1, "first_violation": None}


# ---------------------------------------------------------------------------
# API integration tests: GET /audit/export
# ---------------------------------------------------------------------------


class TestExportAuditEvents:
    def _create(self, client, actor_id, resource_id, **payload):
        return client.post(
            "/audit/events",
            json={"event_type": "TEST", "actor_id": actor_id, "resource_type": "r", "resource_id": resource_id, "payload": payload or {"n": 1}},
        ).json()

    def test_filters_by_actor_id(self, client):
        self._create(client, "alice", "r1")
        self._create(client, "bob", "r2")
        body = client.get("/audit/export", params={"actor_id": "alice"}).json()
        assert len(body["records"]) == 1
        assert body["records"][0]["actor_id"] == "alice"

    def test_filters_by_resource_id(self, client):
        self._create(client, "alice", "r1")
        self._create(client, "alice", "r2")
        body = client.get("/audit/export", params={"resource_id": "r2"}).json()
        assert len(body["records"]) == 1
        assert body["records"][0]["resource_id"] == "r2"

    def test_no_filters_exports_everything(self, client):
        self._create(client, "alice", "r1")
        self._create(client, "bob", "r2")
        body = client.get("/audit/export").json()
        assert len(body["records"]) == 2

    def test_metadata_reports_record_count_and_intact_status(self, client):
        self._create(client, "alice", "r1")
        self._create(client, "alice", "r1")
        body = client.get("/audit/export", params={"actor_id": "alice"}).json()
        assert body["export_metadata"]["record_count"] == 2
        assert body["export_metadata"]["chain_verification_status"] == "INTACT"
        assert ISO_TIMESTAMP_RE.match(body["export_metadata"]["exported_at"])

    def test_metadata_status_reflects_whole_log_not_just_filtered_subset(self, client, isolated_db):
        """A tampered record for a DIFFERENT actor must still flip the export's
        chain_verification_status to BROKEN, since it reports on the whole log's
        health, not just the filtered subset being exported.
        """
        self._create(client, "alice", "r1")
        tampered = self._create(client, "bob", "r2")

        conn = database.get_connection()
        try:
            conn.execute("UPDATE audit_events SET payload = '{\"tampered\":true}' WHERE id = ?", (tampered["id"],))
            conn.commit()
        finally:
            conn.close()

        body = client.get("/audit/export", params={"actor_id": "alice"}).json()
        assert len(body["records"]) == 1  # subset export is unaffected
        assert body["export_metadata"]["chain_verification_status"] == "BROKEN"

    def test_verification_proof_records_are_independently_recomputable(self, client):
        self._create(client, "alice", "r1")
        self._create(client, "alice", "r1")
        body = client.get("/audit/export", params={"actor_id": "alice"}).json()

        proof_records = body["verification_proof"]["records"]
        full_records = body["records"]
        assert len(proof_records) == len(full_records) == 2

        for proof, record in zip(proof_records, full_records):
            recomputed = crypto_utils.compute_record_hash(
                proof["prev_hash"],
                record["id"],
                record["event_type"],
                record["actor_id"],
                record["resource_type"],
                record["resource_id"],
                proof["payload_hash"],
                record["timestamp"],
            )
            assert recomputed == proof["record_hash"]

    def test_bounding_hashes_match_subset_entry_and_exit_points(self, client):
        first = self._create(client, "alice", "r1")
        second = self._create(client, "alice", "r1")
        body = client.get("/audit/export", params={"actor_id": "alice"}).json()

        assert body["verification_proof"]["bounding_start_hash"] == first["prev_hash"]
        assert body["verification_proof"]["bounding_end_hash"] == second["record_hash"]
        assert body["verification_proof"]["genesis_hash"] == database.GENESIS_HASH

    def test_empty_result_has_no_bounding_hashes(self, client):
        body = client.get("/audit/export", params={"actor_id": "nobody"}).json()
        assert body["records"] == []
        assert body["verification_proof"]["bounding_start_hash"] is None
        assert body["verification_proof"]["bounding_end_hash"] is None


# ---------------------------------------------------------------------------
# Unit tests: main.py cursor helpers
# ---------------------------------------------------------------------------


class TestCursorHelpers:
    def test_encode_decode_round_trip(self):
        cursor = main._encode_cursor("2020-01-01T00:00:00Z", 42)
        assert main._decode_cursor(cursor) == ("2020-01-01T00:00:00Z", 42)

    def test_decode_rejects_malformed_base64(self):
        with pytest.raises(Exception):
            main._decode_cursor("%%%not-valid-base64%%%")

    def test_decode_rejects_non_integer_sequence(self):
        bad_cursor = base64.urlsafe_b64encode(b"2020-01-01T00:00:00Z,not-a-number").decode("ascii")
        with pytest.raises(Exception):
            main._decode_cursor(bad_cursor)

    def test_decode_rejects_base64_without_comma_separator(self):
        bad_cursor = base64.urlsafe_b64encode(b"no-comma-here").decode("ascii")
        with pytest.raises(Exception):
            main._decode_cursor(bad_cursor)
