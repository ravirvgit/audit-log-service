# Redaction Design

This document explains the cryptographic approach behind Scenario B
(redaction, retention, and export) -- specifically, how a record's payload
can be legitimately edited after the fact without breaking the tamper-evident
hash chain built for Scenario A. For the API surface itself, see
[ARCHITECTURE.md](ARCHITECTURE.md#scenario-b-redaction-retention-and-export).

## Cryptographic strategy

### The problem

In Scenario A, `record_hash` is a SHA-256 digest over `prev_hash` plus every
field of the record, including a hash of the payload:

```
record_hash = SHA256(prev_hash | id | event_type | actor_id | resource_type
                      | resource_id | payload_hash | timestamp)
```

If you edit `payload` in place, `payload_hash` changes, so `record_hash`
changes, so the *next* record's `prev_hash` no longer matches -- the chain
looks broken from that point forward. The only way to "fix" that with a
naive design is to recompute `record_hash` for the edited record and then
cascade that recomputation through every record after it. That defeats the
purpose of an audit log: an external verifier who cached last week's chain
tip hash would find it silently invalidated, with no way to tell a
legitimate redaction from a cover-up.

But real systems need to redact sensitive fields (GDPR/CCPA erasure
requests, PCI-DSS data minimization, an accidentally-logged secret) without
losing the ability to prove *that an event happened, in this position in
the sequence, with this actor/resource/event_type* -- just not what the
sensitive field's value was.

### The core idea: separate the commitment from the content

`payload_hash` is computed once, at ingestion, and persisted as its own
column (`database.insert_audit_event`) -- it is not merely an intermediate
value thrown away after computing `record_hash`. `record_hash` is a
function of `payload_hash`, not of `payload` itself.

That one design choice is what makes redaction possible: **redaction
overwrites `payload`, but never touches `payload_hash` or `record_hash`.**
Since `record_hash`'s inputs haven't changed, it recomputes to the same
value it always did, so the chain -- including every record after it --
still verifies.

```mermaid
flowchart LR
    subgraph Before["At ingestion"]
        direction TB
        P1["payload:\n{account_number: '4111...', amount: 50}"]
        PH1["payload_hash = SHA256(canonical(payload))"]
        RH1["record_hash = SHA256(prev_hash | ... | payload_hash | timestamp)"]
        P1 --> PH1 --> RH1
    end

    subgraph After["After POST .../redact"]
        direction TB
        P2["payload:\n{account_number: '[REDACTED]', amount: 50}"]
        PH2["payload_hash  (unchanged)"]
        RH2["record_hash  (unchanged)"]
        P2 -.->|"not recomputed"| PH2
        PH2 --> RH2
    end

    RH1 -.same value.-> RH2
```

Put another way: `payload_hash` is a one-way commitment to the record's
*original* content, made at the moment the record was written. Redaction
can erase the content the commitment was made about, but it cannot (and
does not need to) erase the commitment itself -- and the commitment is all
`record_hash`, and therefore the chain, ever depended on.

### Verification model

`GET /audit/verify` (and the full-log check embedded in `GET /audit/export`)
runs the same per-record loop for every record, oldest to newest
(`main._run_chain_verification`):

```mermaid
flowchart TD
    Rec["Current record"] --> Flag{"is_redacted or\nis_archived?"}
    Flag -->|Yes| Stored["payload_hash = record's stored payload_hash\n(trust the original commitment)"]
    Flag -->|No| Live["payload_hash = SHA256(canonical(record.payload))\n(recompute from the live payload)"]
    Stored --> Recompute
    Live --> Recompute["recomputed_hash = compute_record_hash(..., payload_hash, ...)"]
    Recompute --> HashCheck{"recomputed_hash ==\nstored record_hash?"}
    HashCheck -->|No| Broken1["BROKEN: HASH_MISMATCH"]
    HashCheck -->|Yes| ChainCheck{"stored prev_hash ==\nprevious record_hash?"}
    ChainCheck -->|No| Broken2["BROKEN: CHAIN_DISCONTINUITY"]
    ChainCheck -->|Yes| Next["advance to next record"]
```

The only change from Scenario A is *which* `payload_hash` value feeds into
the recomputation. For an untouched record, this is identical to Scenario
A: verification independently recomputes the payload's hash from its live
content, so tampering with `payload` directly is still caught as
`HASH_MISMATCH`, exactly as before. For a record with `is_redacted` or
`is_archived` set, verification trusts the persisted `payload_hash` instead.

### Threat model: what this does and doesn't catch

**Still detected, for every record regardless of redaction/archival status:**
- Any change to `prev_hash`, `record_hash`, `id`, `event_type`, `actor_id`,
  `resource_type`, `resource_id`, or `payload_hash` itself -- `HASH_MISMATCH`.
- Any inserted, deleted, or reordered record -- `CHAIN_DISCONTINUITY`.
- Direct tampering of `payload` on a record that is *not* redacted or
  archived (the common case) -- `HASH_MISMATCH`, exactly as in Scenario A.

**No longer detected, once `is_redacted` or `is_archived` is set:**
- Direct tampering of the live `payload` column's content. This is the
  intended trade-off for a *redacted* record (verification is supposed to
  stop caring what the redacted payload says). It is a **broader exemption
  than strictly necessary for an *archived-but-not-redacted* record**,
  since archiving alone never touches the payload -- an archived record's
  live payload would still hash correctly if it were checked. This
  blanket rule (`is_redacted OR is_archived`) was a deliberate, explicit
  design decision for this system, not an inherent requirement of
  redaction itself, and is worth re-confirming if the retention policy is
  ever expected to carry the same tamper-evidence guarantees as an
  unarchived record.

### What no hash-chain-only design can prove

A hash chain proves *internal consistency*: "this sequence of records is
well-formed and has not been edited, inserted, deleted, or reordered since
it was written, as far as the data in this file shows." It cannot prove
that the file itself hasn't been wholesale rewritten by someone with direct
write access to the SQLite database -- there is no external anchor (no
digital signature over each record, no append-only/WORM storage, no
periodic publication of the chain tip to an out-of-band, immutable
location). Anyone with raw DB access could, in principle, regenerate an
entirely different but internally self-consistent chain from scratch. This
is the same limitation `git` has against someone who controls a repository
outright and force-pushes a rewritten history. Closing this gap (if ever
required) would mean adding one of: asymmetric signatures over each
`record_hash` using a key the log-writing service doesn't itself hold,
periodic external timestamping/notarization of the chain tip, or
write-once storage for the database file. None of that is implemented
here; it's out of scope for this assignment, but stated explicitly rather
than implying a stronger guarantee than what's actually provided.

## Trade-off analysis

Three approaches to committing a payload's hash were considered. The
comparison assumes the same threat this document's title is about: how do
you let a payload's sensitive fields be redacted later without breaking
`record_hash`, and what does each approach cost you in return?

| Approach | How it works | Redaction impact | Cost |
| --- | --- | --- | --- |
| **Persistent `payload_hash` column (chosen)** | Hash the whole canonical payload once at ingestion; persist it in its own column; `record_hash` depends on this value, never on live `payload` | Redaction overwrites `payload` only; `payload_hash`/`record_hash` untouched, chain stays valid | Simple, and matches Scenario B/C's "recipient independently recomputes the hash offline" requirement exactly -- but see the brute-force caveat below |
| **Field-level Merkle tree** | Hash each payload field independently; combine into a Merkle tree; `record_hash` commits to the tree root instead of one `payload_hash` | Redacting a field drops its leaf preimage but keeps a Merkle proof stub; *other* fields stay independently provable untouched | Finer-grained integrity (per-field, not all-or-nothing), but a Merkle library, more stored bytes per record, and proof construction/verification code -- meaningfully more complexity than this project's scope calls for, and it does not by itself solve the brute-force caveat below either |
| **Salted digest** (`payload_hash = SHA256(salt \| canonical(payload))`) | A per-record random salt is mixed in before hashing, and persisted alongside the hash | Same redaction mechanics as the chosen approach -- salting only changes how `payload_hash` is *computed*, not how redaction preserves it | Defeats generic, precomputed rainbow-table attacks, but only if the salt is *not* handed out with the hash. Scenario B/C's export bundle exists specifically so a recipient can recompute and verify the hash offline -- which requires giving them the salt too, at which point salting adds no protection against a targeted guess-and-hash attack. Keeping the salt secret instead would break that same offline-verification feature for every record, not just redacted ones. |

**The brute-force caveat, stated plainly:** `payload_hash` is a hash of the
*entire* canonical payload, not a hash-per-field. After redaction, every
*non*-redacted field in that payload is still visible in plaintext (e.g.
`{"account_number": "[REDACTED]", "amount": 50}` -- `amount` is right
there). An attacker who has `payload_hash` and can see every other field's
real value needs to guess only the redacted field(s) to test a match:
reconstruct the canonical JSON with the known fields plus a candidate
value, hash it, and compare. For a field with genuinely large entropy
(a full card number, a random token) this is infeasible. For a low-entropy
field (a 4-digit PIN, a small enum, a short numeric code) it is not --
brute-forcing every candidate is cheap. **This is a real limitation of the
chosen design, not a hypothetical one**, and neither of the other two
approaches solves it on their own (a per-field Merkle leaf hash has the
exact same problem, one field at a time; an exported salt doesn't help a
targeted attacker who already has it). Closing this gap for genuinely
low-entropy fields would mean a dedicated password-hashing-style KDF
(e.g. Argon2/scrypt, deliberately slow rather than merely salted) applied
specifically to those fields before they ever reach `payload_hash` -- not
implemented here, and worth flagging to whoever owns what kinds of values
are allowed into a redactable `payload` field in the first place.

Two further alternatives, specific to the redaction mechanism itself
rather than the hash function:

1. **Cascading rehash on redaction** -- recompute `payload_hash` from the
   redacted payload, then recompute `record_hash` for that record and
   every record after it (since each later record's hash transitively
   depends on it). Rejected: this requires rewriting a potentially large
   tail of "immutable" history on every redaction, and defeats the audit
   trail's purpose -- a verifier who cached an earlier chain tip hash
   would see it silently invalidated, unable to distinguish a legitimate
   redaction from tampering.

2. **Physically deleting the sensitive row, leaving a hash-only tombstone**
   -- rejected outright: it breaks the chain (the next record's
   `prev_hash` would reference a hash with no backing row) and defeats the
   purpose redaction is meant to serve in the first place -- proving an
   event occurred, just not what its sensitive values were.

## Retention policy

`POST /audit/retention/apply` implements retention as a **soft archival
flag**, never a physical deletion:

- It sets `is_archived = 1` and `archived_at` (a UTC timestamp) on every
  matching row (`database.archive_events_older_than`). The row, its
  `payload`, and every hash field are otherwise untouched.
- Archived records remain fully queryable through `GET /audit/events` and
  are still walked, in the same position in the chain, by
  `GET /audit/verify` -- with the same `payload_hash` exemption described
  in "Verification model" above.

**Why not physical row deletion?** Deleting a row breaks the chain in
exactly the way described for the tombstone alternative above: the next
surviving record's `prev_hash` would point to a `record_hash` with no
backing row, which `GET /audit/verify` would (correctly) report as
`CHAIN_DISCONTINUITY`. A retention policy whose enforcement mechanism
itself corrupts the audit trail defeats the point of having one. Soft
archival gets the practical benefit retention is usually for --
distinguishing "old, less operationally relevant" records from current
ones, e.g. for a separate storage tier or a slower default query path --
without ever sacrificing chain integrity to get it.

## Export, briefly

`GET /audit/export` hands a recipient: the matching records (with their
current, possibly-redacted payloads), the *whole log's* chain verification
status at export time (not just the filtered subset), and a
`verification_proof` letting the recipient independently recompute each
exported record's own `record_hash` from its `payload_hash` and other
fields. A filtered export's records are usually not adjacent to each other
in the full chain, so the proof cannot show the subset forms a contiguous
mini-chain on its own -- only a full, unfiltered export can be fully
reconstructed and verified offline.
