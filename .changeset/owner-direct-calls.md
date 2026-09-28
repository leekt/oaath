---
"@oaath/sdk": minor
---

Add owner mode to createOAAth for existing ECDSA-root Kernel v3.3 accounts.
Review and send one UserOperation with a connected wallet, without an issuer,
Grant, or enable envelope. Reuse the durable Operation journal and exact recovery;
default IndexedDB prevents another send while the account/chain slot is unresolved.
Default viem ports now serve v3.3 account reads through the public RPC pool.
