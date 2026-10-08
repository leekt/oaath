---
"@oaath/sdk": patch
---

An OAuth-approved Grant's `revoke()` now also asks the issuer once to invalidate it, proven by the Grant's own session key, and resolves to `{ issuer: "invalidated" | "refused" | "unavailable" | "not-attempted" }`. The local revocation never waits on or depends on the issuer.
