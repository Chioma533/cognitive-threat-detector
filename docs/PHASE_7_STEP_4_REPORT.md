# Phase 7, Step 4: SQLite Persistence

## Overview

Phase 7 Step 4 adds a durable SQLite-backed implementation of the existing
`IncidentStore` protocol. It persists incident snapshots, recommendations,
investigation notes, and append-only audit events. The framework-independent
incident service and in-memory store remain available and unchanged in behavior.

## Database schema

The repository initializes three tables idempotently:

- `incidents`: primary-key `incident_id`, integer `revision`, and JSON for the
  complete `IncidentRecord`.
- `investigation_notes`: unique primary-key `note_id`, incident foreign key,
  UTC creation timestamp, and JSON for the complete note.
- `incident_audit_events`: unique primary-key `event_id`, incident foreign key,
  UTC occurrence timestamp, and JSON for the complete audit event.

Foreign-key enforcement is enabled on each repository connection. Chronology
indexes support ordered retrieval of notes and audit events.

## Repository and serialization

`SQLiteIncidentStore` uses Python's built-in `sqlite3` module and accepts a
database path at construction. Each operation opens and closes its own
connection. Complete records are serialized as JSON; `datetime` values use an
explicit marker and ISO-8601 representation, and are reconstructed as
timezone-aware UTC datetimes. JSON serialization rejects non-finite numbers.
Retrieval creates new objects, so changes by callers do not affect stored data.

The repository implements the existing create, compare-and-update, and retrieval
methods. It contains no incident triage or lifecycle policy and exposes no audit
event update or delete operation.

## Transaction and concurrency guarantees

Creation writes the incident and its initial audit event in one transaction.
Updates use `BEGIN IMMEDIATE`, verify the stored revision, enforce the supplied
revision increment, and condition the incident update on the expected revision.
The audit event and optional note are inserted before the transaction commits.
Failures roll back every write in the operation.

SQLite uniqueness conflicts are translated to `IncidentConflictError`.
Transactions and revision checks are database-enforced, not dependent on a
process-local Python lock. New incidents start at revision 0; each accepted
update increments the revision by exactly one.

## Test coverage

`backend/tests/test_sqlite_repository.py` covers restart persistence, nested
assessment and recommendation serialization, UTC timestamp reconstruction,
transaction rollback for creation and updates, uniqueness, unknown incidents,
defensive retrieval, chronological ordering, revision checks, and competing
updates from separate repository instances.

## Known limitations

This SQLite implementation is intended for the current single-instance
prototype. It does not establish production multi-instance deployment readiness.
Production use requires separate review of deployment topology, backup and
restore, retention, access controls, operational monitoring, and data
protection. The repository does not add API routes, authentication, incident
deduplication, or response execution.
