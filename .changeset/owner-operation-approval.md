---
"@oaath/sdk": patch
---

Add `requestOwnerOperationApproval({ issuer, clientId, redirectUri, request })`: the account root approves one owner operation in the issuer's portal popup, and the SDK returns it verified (`verifyOwnerOperation`) for the caller's own submission.
