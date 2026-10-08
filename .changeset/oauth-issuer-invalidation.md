---
"@oaath/sdk": patch
---

An OAuth-approved Grant's `revoke()` now also asks the issuer once to invalidate it, authenticated by the Grant's own session key (an `OAAth-Grant-Proof` bound to the grant, method, path and time), and resolves to `{ issuer: "invalidated" | "refused" | "unavailable" | "not-attempted" }`. The local revocation never waits on or depends on the issuer, and the realm stores no access token.
