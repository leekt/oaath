---
"@oaath/sdk": patch
---

After `loginWithOAAth`, `requestPermission` and `requestOwnerOperationApproval` send the login's id_token as the OIDC `id_token_hint`, so the issuer's portal opens straight on the signature for the signer and account the user already chose. The hint stays in page memory and is sent for at most an hour after the login; without a login, requests are unchanged.
