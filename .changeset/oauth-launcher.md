---
"@oaath/sdk": patch
---

`approvals.launch` on the oauth realm opens the portal without a popup (for example `chrome.identity.launchWebAuthFlow`) and resolves with the redirect URL, checked exactly like a popup's response.
