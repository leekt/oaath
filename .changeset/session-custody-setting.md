---
"@oaath/sdk": minor
---

Session key custody joins the one optional `session` setting:
`session?: { kind?: "ecdsa" | "webauthn", custody?: "browser" | "application-backend" | "oaath-hosted", ... }`.
Defaults are unchanged. The injected composition no longer accepts
`sessionSigner`; remote custody comes only from the service bootstrap, which owns
it. `custody` is a requirement assertion: a mismatch with the declared custody, a
passkey under remote custody, or remote custody under wallet approvals fails
with `oaath_client_capability_unsupported` (source `session_custody_unsupported`)
before any session key, store, or signer request exists. `OaathSessionCustody`
is exported. The protocol wire is unchanged.
