---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Add issuer-free local mode for existing Kernel v3.3 accounts with browser or local
viem wallets. Persist an encrypted session before one typed-data approval, then
reuse the scoped Grant and recover operations after reopening. The same client
supports owner execution. Local disconnect revokes installed and unused approvals
before deleting key custody; close cancels pending authority publication and keeps
failed resource cleanup retryable.

Refresh the Grant revision after admitting an unused-approval revocation operation,
so its finalized evidence commits without a false concurrent-writer conflict.

Expose fresh chain ports and typed-data wallet signing in the public local owner
fixture for adopter tests. The fixture uses local Anvil and fixed gas estimates.
