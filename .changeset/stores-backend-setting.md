---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": patch
---

Breaking: `createOAAth`'s `stores` option names a backend instead of taking
seven adapters. `{ kind: "indexeddb" }` is the default (optionally with
`factory` and `name`), and `{ kind: "memory" }` runs tests and non-browser
development with no per-store wiring. Either backend accepts individual adapter
overrides, e.g. `{ kind: "memory", operations: postgresJournal }`; the backend
fills only the stores that are not overridden. Owner-only execution takes the
same shape and uses only `operations`.

Memory is never a fallback: service-approved clients no longer drop to memory
where IndexedDB is missing, and every mode fails with
`oaath_client_store_unavailable` instead. A memory restart forgets operation
IDs, and a forgotten operation is never resubmitted.
