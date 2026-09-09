---
"@oaath/protocol": patch
"@oaath/server": patch
---

Add a service-owned directory for personal/team workspaces, application-member
bindings, accounts, owner-device references, and account selections. Memory and
PostgreSQL stores use revision-checked document replacement. Bootstrap resolves
current membership on every request; stale selections confer no access. Reuse
the protocol's account/owner-validator capture in directory and bootstrap records.
