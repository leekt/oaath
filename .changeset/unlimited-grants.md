---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Unbounded grants: a GrantPolicy may have `validUntil: null` (no expiry policy is installed) and `perChainOperationLimit: null` (no operation or rate limit is installed), so a policy with neither installs only the call policy. A null limit hashes as count zero, which no limited policy can produce; an unlimited request may be approved with a limit, never the reverse. The OAAth portal flags an unbounded grant before the root signs.
