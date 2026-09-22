"""Cryptographic helpers for the append-only audit log's hash chain.

Every audit record is bound to the one before it by including the
previous record's hash as an input to its own hash. Tampering with any
field of any record -- or deleting/reordering records -- changes the
hashes of everything after it, which `GET /audit/verify` can detect.
"""

import hashlib
import json
from typing import Any, Dict


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """Compute a canonical SHA-256 hash of an event payload.

    Keys are sorted and separators are fixed so that two payloads with
    the same data but different key ordering or whitespace hash
    identically.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_record_hash(
    prev_hash: str,
    record_id: str,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload_hash: str,
    timestamp: str,
) -> str:
    """Compute the SHA-256 hash for a single audit record.

    The hash covers every immutable field of the record plus the hash
    of the previous record, which is what makes the sequence a chain
    rather than a set of independently hashed rows.
    """
    canonical = "|".join(
        [
            prev_hash,
            record_id,
            event_type,
            actor_id,
            resource_type,
            resource_id,
            payload_hash,
            timestamp,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
