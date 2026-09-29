---
"@oaath/sdk": minor
"@oaath/server": minor
"@oaath/testing": minor
---

`OperationStore.list(scope)` returns the current record of every lane in one
(Grant, chain, kind) scope, including the default lane. It fails closed when a
listed record belongs to another scope, repeats a lane, or is malformed.

Breaking advanced API change: `OperationStoreAdapter` requires
`list(scope)`, and `OperationStoreScope` is exported. The memory, IndexedDB,
PostgreSQL and SQLite test adapters implement it. Custom adapters must return
every current lane record for the exact scope.
