---
"@oaath/sdk": minor
---

Add createViemChainPorts for public-RPC account reads, finalized policy usage,
nonce/fee quotes and observation, with bounded retry/failover. Configure bundler
and optional paymaster URLs separately. Submissions and sponsorship stages are
single-attempt; every request shares an explicit finite instance budget.
