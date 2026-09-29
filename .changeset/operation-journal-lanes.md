---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": minor
"@oaath/testing": minor
---

Key the Operation journal per caller-reserved lane. `oaath.operation/v4` records
name their `lane` (`null` for the default lane, or an exact `{ id, key }`
execution lane), and `OperationStoreKey` gains an optional `lane` key. Each
(Grant, chain, kind, lane) slot keeps its own current record, archive and
one-unresolved-Operation rule; a record never lands under another lane's key.
No public API sends on a non-default lane yet.

Breaking persisted-state change: `oaath.operation/v3` records and
`oaath.operation-store-record/v2` envelopes are rejected without migration.
IndexedDB schema 15 recreates older local state. PostgreSQL uses new
`oaath_operation_lane_v2` and `oaath_operation_archive_v2` tables, and the
SQLite test store uses schema `oaath.sqlite-test-store/v3`; recreate them.
