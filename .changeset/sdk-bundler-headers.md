---
"@oaath/sdk": patch
---

Add optional per-chain `bundlerHeaders` to Cetane chain ports, sent only to the bundler (for example a bundle_rs `x-api-key`). Header values that are not strings or contain CR/LF are refused.
