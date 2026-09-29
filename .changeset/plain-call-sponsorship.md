---
"@oaath/sdk": minor
---

Allow an explicit registered ERC-7677 `payer: { kind: "paymaster-service" }` on plain Grant and owner
sendCalls. The existing sponsorship owner finalizes gas and paymaster data before
the operation is journaled or signed. reviewCalls reports the selected service
without invoking it. Failed sponsorship never falls back to an unsponsored send.
