---
"@oaath/sdk": minor
---

Export `credentialKey` from `@oaath/sdk/kernel` for owner approval and public
session preparation from public credential profiles. The factory validates
the complete versioned credential and installs byte-identical public material
to its signing profile. It has no signing capability and never verifies a
signature as accepted. WebAuthn estimation uses an ABI-valid dummy assertion.

Applications can derive and verify a passkey permission without pretending to
own its authenticator. This adds no persisted state, approval or retry behavior.
