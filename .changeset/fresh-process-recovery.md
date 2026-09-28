---
"@oaath/testing": minor
---

Add durable direct-Grant local Anvil fixtures and a read-only recovery client
that reopens SDK state after OS process loss without credentials or resubmission.
Receipt discovery now reads actual EntryPoint logs instead of process-local
transaction lookup. Expose SQLite adapters for SDK composition and bump the
disposable test database schema to v2; old files must be recreated.
