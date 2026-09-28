---
"@oaath/protocol": minor
"@oaath/sdk": minor
---

Retain the acknowledged submission route and direct transaction hash in operation
records, and expose a matching route from finalized `operation.execution()`.
Acknowledgement never authorizes resubmission or proves inclusion. Custom adapters
can omit route evidence when it is unknown; default viem ports report bundler
acknowledgements.

Operation records advance to `oaath.operation/v3`, rejecting older records.
IndexedDB schema 14 recreates older local state without migration, deleting
retained keys, Grants, and operation history. Reconnect and authorize fresh
permissions; resetting local storage does not revoke onchain authority.
