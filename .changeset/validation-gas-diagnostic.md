---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": minor
---

Report ABI-proven AA23 empty validation reverts with a closed likely-out-of-gas
diagnostic and the requested verification gas limit. Preserve that hint through
direct and relayed preparation, sponsorship, provider errors and uncertain
submission outcomes without retaining raw provider errors or enabling retries.
Forward configured enable gas floors through service bootstrap.
Keep the paymaster's public service identity canonical while retaining the exact
configured transport endpoint.
