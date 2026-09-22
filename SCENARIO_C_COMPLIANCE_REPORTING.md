# Scenario C — Ambiguous: Compliance Reporting

## Product ask

> "Regulators need to be able to audit access to client account data."

This is under-specified along several axes at once -- what counts as
"access," what counts as "client account data," what form regulators need
the output in, and how the query needs to perform. Rather than guess
silently, each axis below is broken into a specific question and the
assumption this system would proceed under until a stakeholder confirms or
corrects it.

## Ambiguity decomposition

| # | Question | Assumption |
| --- | --- | --- |
| 1. Access scope | Does "access" mean read-only views, state mutations, failed authorization attempts, or admin exports? | Audit `READ`, `EXPORT`, `UPDATE`, and `DELETE` events on account resources. Exclude background system health-checks. |
| 2. Data scope | What constitutes "client account data"? Is it an account ID, a user profile, or specific PII attributes? | Scope explicitly to `resource_type = "CUSTOMER_RECORD"` or `"BANK_ACCOUNT"`, identified by `resource_id`. |
| 3. Output format | Do regulators require raw database dumps, formatted summary PDFs, or cryptographically verifiable bundles? | Deliver an aggregated JSON compliance report backed by bounding cryptographic proof from the Scenario B export engine. |
| 4. Query model | Are queries real-time or async? What time window must be filterable? | Endpoint must respond synchronously within 2 seconds for date ranges ≤ 365 days, powered by a composite index on `(resource_type, resource_id)`. |

## Clarified requirement statement

Once the four assumptions above were accepted as a working baseline, they
were normalized into a concrete functional specification -- this is what
was actually built, and it narrows assumption 1 down to the three event
types a client account can be "accessed" through:

> **FR-C1.** The system SHALL expose a synchronous, read-only endpoint,
> `GET /audit/reports/compliance-access`, accepting a required `resource_id`
> (the client account identifier) and a required `[from_ts, to_ts]` UTC
> ISO-8601 time window.
>
> **FR-C2.** The endpoint SHALL return every audit event recorded for that
> `resource_id` whose `event_type` is one of `ACCOUNT_READ`,
> `RECORD_UPDATED`, or `DATA_EXPORT`, within the given window, ordered
> chronologically (oldest first).
>
> **FR-C3.** The response SHALL include: the total matching event count;
> the count and sorted list of distinct `actor_id`s represented; a count of
> matching events broken down by `event_type`, including an explicit zero
> for any of the three allow-listed types with no matches; and the full
> list of matching events.
>
> **FR-C4.** The response SHALL include a `verification_proof` comprising
> the chain's constant genesis sentinel, the `bounding_start_hash`/
> `bounding_end_hash` of the matched subset within the full chain, and a
> `chain_status` reflecting whether the *entire* underlying audit log --
> not only the matched subset -- was internally consistent at request
> time.

## Technical design & scope boundary

**Implemented:** `GET /audit/reports/compliance-access` (see `main.py`,
`database.export_events_by_target`), satisfying FR-C1 through FR-C4 above.
It is not a new persistence mechanism -- it extends the same
`export_events_by_target` engine Scenario B's `GET /audit/export` uses,
adding `event_types`/`from_ts`/`to_ts` filter parameters to it, exactly as
assumption 3 anticipated ("backed by bounding cryptographic proof from the
Scenario B export engine").

**Explicitly scoped out, with justification:**

- **Async report generation (a job queue producing a downloadable artifact
  later, rather than a synchronous response).** FR-C1/assumption 4 called
  for a *synchronous* response, and a single indexed SQL query comfortably
  meets that shape today -- adding queue/worker/polling infrastructure now
  would be solving a scaling problem that hasn't been demonstrated to
  exist yet. If real query volume or window size ever makes the
  synchronous path too slow, that's the point to revisit this, not before.
- **PDF (or other formatted-document) generation.** Assumption 3 chose a
  JSON bundle over "formatted summary PDFs" specifically so the audit log
  service's one job stays producing verifiable *data*, not rendering
  presentation-layer documents. A PDF (or any other regulator-facing
  format) can be generated from this JSON by a separate downstream
  consumer without this service needing to own document rendering,
  fonts, layout, or any of the concerns that come with it.
- **Gateway-level RBAC / regulator-specific authorization.** This is the
  same no-auth gap flagged throughout this project (see
  [README.md](README.md#final-engineering-summary)), stated here in scope
  terms: there is no authentication or role model anywhere in this
  codebase yet to attach a "regulator" scope to. Building bespoke
  authorization logic for this one endpoint, ahead of a real authn/authz
  layer for the API as a whole, would mean solving the problem twice --
  once narrowly here, and again properly later. The correctly-sequenced
  move is to treat this as a blocking prerequisite for production use (see
  "Open questions" below), not to bolt on a one-off check now.

## Fit against the current system

The assumptions above were chosen partly because they map cleanly onto
what Scenarios A and B already built, which makes them a reasonable
default and a cheap starting point -- but two of the four also expose real
gaps worth calling out rather than glossing over:

- **Assumption 2 and 4 (data scope, query performance)** are already
  supported today. `resource_type`/`resource_id` are existing, indexed
  columns (`idx_audit_events_resource`), and `GET /audit/events` /
  `GET /audit/export` already filter on both.
- **Assumption 3 (output format)** is close to what `GET /audit/export`
  already returns (Scenario B): a JSON bundle of matching records plus a
  `verification_proof` a regulator could check offline. A compliance
  report could plausibly be this same endpoint, filtered to
  `resource_type IN ("CUSTOMER_RECORD", "BANK_ACCOUNT")`, rather than a
  new one.
- **Assumption 1 (access scope) has a real gap.** This service can only
  report on events it is *told about* -- it has no way to observe a read,
  update, or delete happening somewhere else in the system unless the
  service performing that action calls `POST /audit/events` itself. If
  account-data *reads* aren't already instrumented to log an audit event
  today, "audit READ access" is not a query-layer problem to solve here;
  it is an instrumentation project across every service that touches
  account data, which is a materially larger scope than this document's
  four assumptions imply.
- **No authentication or authorization exists anywhere in this codebase
  today.** Every endpoint, including `GET /audit/export`, is unauthenticated.
  A regulator-facing compliance endpoint that returns client PII/account
  data is a fundamentally different trust boundary than an internal
  service-to-service audit log, and shipping it on the current
  no-auth foundation would be a significant, avoidable risk. This has to
  be resolved before implementation, not treated as a follow-up.
- **The 2-second SLA (assumption 4) is asserted, not verified.** Nothing
  in this codebase has been load-tested against a 365-day range; the
  claim should be treated as a target to validate, not a given.

## Open questions before implementation

1. Confirm assumptions 1-4 above with product/compliance stakeholders --
   they are starting points, not decisions.
2. Decide whether "READ access" auditing requires instrumenting every
   account-data read path across the system, and if so, scope that as
   its own project rather than folding it into this service's work.
3. Define the authentication/authorization model for regulator access
   before exposing any endpoint that returns client account data.
4. Load-test the 2-second SLA claim against a realistic data volume and
   365-day range once the above are resolved.
