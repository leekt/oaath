---
"@oaath/sdk": patch
---

Cetane chain ports quote `maxFeePerGas` with 2x base-fee headroom (Cetane's default) instead of 1.2x, so bundlers that require at least their own gas-price quote (e.g. Pimlico) accept the operation.
