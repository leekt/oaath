---
"@oaath/sdk": patch
---

Expose stable operation IDs and exact local operation recovery through
`grant.getOperation({ chain, id })`, including observation after grant expiry.
`sendCalls` now starts fresh calls without waiting for inclusion and rejects an
occupied lane instead of returning an older unresolved operation.
