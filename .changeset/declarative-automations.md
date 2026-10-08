---
"@oaath/automation": patch
"@oaath/automation-server": patch
---

Add declarative automations. `@oaath/automation` owns the definition schema, plan terms, the derived Grant policy and the service client; `@oaath/automation-server` is a self-hostable service (HTTP API, scheduler and executor over PostgreSQL) that obtains Grants as an OAuth client of an OAAth issuer and executes each occurrence at most once.
