---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": minor
---

URL (issuer) mode accepts the same optional `session` setting as local mode:
`createOAAth({ url, session: { kind: "webauthn", ...webauthnKeyInput } })`. The
shared type is now `OaathSession` (was `OaathLocalSession`). The owner reviews and
installs the passkey as the operator credential; no session key is generated or
stored, and a deployment declaring backend or hosted session custody refuses it
with `oaath_client_capability_unsupported`. The server and phone consent already
carry a WebAuthn operator credential unchanged.

`oaath doctor` reports `passkeySessionsReady` (schema
`oaath.runtime-readiness/v2`): the WebAuthn signer and P-256 verifier with their
pinned runtime hashes. It never affects `ready` or the exit code.
`deploy-runtime` now also deploys both when missing.

`@oaath/testing`'s `createLocalAnvilFixture` serves `GET /bootstrap` and adds
`openServiceClient({ session? })`; its owner derives permission packages from the
reviewed operator credential.
