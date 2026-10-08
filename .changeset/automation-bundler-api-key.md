---
"@oaath/automation-server": patch
---

Add optional `AUTOMATION_BUNDLER_API_KEY_<chainId>`: when set, the executor sends it to that chain's bundler only, as the `x-api-key` header (bundle_rs client authentication).
