# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

`@oaath/sdk/kernel` exposes `prepareKernelPhonePermissionApproval` for the
owner-phone service integration. It binds a canonical permission request's
account using public credentials and configured reads, derives its policy
packages through `createKernelRuntime`, and returns the existing Kernel signing
request. `complete(phoneArtifact, decidedAt)` verifies the P-256 signature and
returns the permission decision plus install approval consumed by the browser
client. The caller owns phone transport and install-nonce allocation; the helper
does not submit or persist anything. It supports the P-256 owner phone and the
current ECDSA/WebAuthn operator profiles, using the Kernel factory route.

The headless Grant provider returns `4200` for `wallet_showCallsStatus` unless
the adopter supplies a wallet-owned status presenter. Executable
`wallet_sendCalls` entries without `to` are valid contract-creation requests,
but OAAth does not own a creation policy and refuses them with its fixed
provider execution error (`-32000`).

The Draft ERC-7836 prepared-call profile accepts only the approved operator's
external signature. `secp256k1` supports `frontend` or `application_backend`
custody; `webauthn-p256` supports `frontend` custody only. `oaath_hosted` is
rejected before preparation.

Its opaque five-minute context is current-version-only, durable, and consumed
once. A recreated IndexedDB realm resumes the retained prepared operation and
any ambiguous send without preparing, signing, or submitting another operation;
older, unreadable, stale, and already-consumed contexts do not authorize a new
operation.
