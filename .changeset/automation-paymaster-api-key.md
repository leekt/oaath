---
"@oaath/automation-server": patch
---

Add optional `AUTOMATION_PAYMASTER_API_KEY_<chainId>`: when set, the executor sends `{ apiKey }` as the ERC-7677 paymaster context (as paymaster-rs accepts it) instead of `{}`.
