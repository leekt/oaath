# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

`grant.sendCalls({ chain, calls })` starts a new operation and returns its handle
without waiting for inclusion. Retain `{ chain: operation.chainId, id: operation.id }`
with the application's job. An unresolved operation occupies that grant/chain
lane, so another send fails with `oaath_client_state_conflict`.

After reconnecting and resuming the grant, `grant.getOperation({ chain, id })`
recovers that exact execution from local history, including terminal records
after a later operation replaces the lane. Lookup and observation do not quote,
sign, or submit, and work after grant expiry or revocation. `null` means no
matching retained record, never permission to retry a send.

Custom deployment quotes receive the selected Kernel `mode` and `validation`.
Choose a nonce namespace, encode its EntryPoint key with `encodeKernelV4NonceKey`,
and read that key's sequence. The root, enable, and standard permission paths
have separate nonce domains; the SDK supplies the authority and the deployment
supplies its current chain sequence and gas.

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
