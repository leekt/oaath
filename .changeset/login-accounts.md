---
"@oaath/sdk": patch
---

`loginWithOAAth` returns `accounts`: every account the signer is an active member of, from the id_token's `oaath_accounts` claim. A malformed claim refuses the login with `oaath_client_identity_invalid`.
