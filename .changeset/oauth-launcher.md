---
"@oaath/sdk": patch
"@oaath/testing": patch
---

`approvals.launch` on the oauth realm opens the portal without a popup (for example `chrome.identity.launchWebAuthFlow`) and resolves with the redirect URL, checked exactly like a popup's response. `@oaath/testing/anvil` adds `createLocalOAuthIssuer`, a loopback issuer whose root approves at once, for local proofs.
