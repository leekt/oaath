---
"@oaath/sdk": patch
---

Support viem local accounts for existing Kernel v3.3 owner signatures and the
connected-EOA handleOps fallback. Local signing keeps the configured signing
capability instead of changing it into an RPC account; local fee payment uses
the wallet's transaction action with the captured account.

The Operation journal still owns the occupied lane and saved submission. Only
a conclusive pre-acceptance bundler rejection permits the same signed operation
to use handleOps once. Pending, unreadable, closed, and ambiguous submissions
never permit another send. Closing releases runtime resources; recreating the
client observes the retained operation without a wallet or another signature.

Local Anvil verifies browser and local owner execution, exact fallback bytes,
and recovery from a newly opened SQLite store. Unit tests cover local signing
without RPC signing and reject fallback after ambiguous errors. No live chains
or hosted bundlers were used.
