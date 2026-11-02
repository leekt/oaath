---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

A counterfactual Kernel 0.3.3 account's owner operation may deploy it: `prepareOwnerOperation({ ..., deployed: false, accountIndex })` adds its MetaFactory deployment, re-derived from the root owner and index, and `verifyOwnerOperation` accepts exactly that deployment at the account's own address, so `requestOwnerOperationApproval` covers sponsored org-wallet activation. The portal can import such a wallet before it is deployed by its account index.
