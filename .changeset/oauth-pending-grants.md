---
"@oaath/sdk": patch
---

OAuth-approved Grants may wait for the account root. When the issuer answers `authorization_pending`, `requestPermission` resolves to `{ state: "pending", requestId, expiresAt }` and journals the issued code; `connection.redeemPending()` makes one token request per call, survives a reload, and adopts the Grant once the root approves. A rejection fails with `oaath_client_permission_rejected`.
