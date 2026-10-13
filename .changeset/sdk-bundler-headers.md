---
"@oaath/sdk": patch
---

Add optional per-chain `bundlerHeaders` to Cetane chain ports, sent only to the bundler (for endpoints that accept an `x-api-key` header). Header values that are not strings or contain CR/LF are refused.
