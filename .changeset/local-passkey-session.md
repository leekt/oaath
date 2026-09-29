---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Local mode accepts a caller-supplied passkey session:
`createOAAth({ mode: "local", ..., session: { kind: "webauthn", ...webauthnKeyInput } })`.
Omitting `session` (or `{ kind: "ecdsa" }`) keeps the generated, wrapped ECDSA
session key. The ECDSA owner approves once; enable-on-first-use, the operation
journal, `resume()` and `revoke()` are unchanged. No private material is
persisted for a passkey: the device identity derives from its public credential,
and the Grant record's operator credential is the only stored session fact.

The pinned WebAuthn signer verifies with `usePrecompiled = false` through Daimo's
P256Verifier at `0xc2b78104907f722dabac4c69f826a522b2754de4`, so RIP-7212 does
not change the path. A WebAuthn session bind now requires that verifier's exact
runtime code hash and fails closed with `kernel_runtime_signer_unavailable`
(`oaath_client_capability_unsupported` in local mode) before owner review or any
signature. The Anvil Kernel stack fixture now deploys the verifier.
