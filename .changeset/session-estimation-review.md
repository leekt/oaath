---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Grant `reviewCalls` accepts `estimate: true` and reports whether the exact session
operation was estimated or received a conclusive account-validation rejection.
The check creates no durable operation, signature or submission. Only a canonical
EntryPoint account-validation error captured during estimation produces the
rejection result; provider prose, diagnostics, caller-created errors, timeouts and
submission failures do not. Default reviews report `not-estimated`.
