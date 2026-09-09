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
client. The caller owns phone transport; the helper does not submit or persist
anything. It supports the P-256 owner phone and the
current ECDSA/WebAuthn operator profiles, using the Kernel factory route.

Phone preparation derives its install nonce with
`kernelPermissionInstallNonce(hashPermissionRequest(request))`: the first 192
hash bits select a request-specific Kernel install key at sequence zero. The
same request recreates the same signing packet, while different requests can
install in different orders across chains. This requires an unused key and
Kernel's global `validNonceFrom()` to remain zero on each destination chain;
accounts with an advanced global minimum require separate reconciliation.
The install nonce is separate from the EntryPoint operation nonce above.

For an untouched chain, `encodeKernelV4InstallNonceInvalidationCall({ account,
installNonce })` encodes an owner self-call that advances that approval's key
to the next sequence. `encodeKernelV4InstallNonceRead({ key })` encodes the
account's `nonce(uint192)` read for checking its effective sequence. An already
consumed or invalidated nonce requires observation; repeating the self-call can
revert because Kernel requires an increase. Installed permissions still need
uninstall calls. These codecs do not submit, establish finality, or complete
configured-chain revocation.

`prepareKernelPhoneRevocation` prepares one self-funded P-256 owner operation
from a canonical permission request and its retained install approval. Supply
the chain, root operation nonce, gas and the effect supported by chain evidence:
`invalidate-install` or `uninstall-permission`. Retain its `prepared` operation
and `signingRequest` before requesting owner consent. The phone request binds
the workspace, application, install scope, chain, EntryPoint and exact removal
calls; it contains no enable signature. `complete(phoneArtifact)` verifies and
returns the signature for that operation. Preparation and completion never
submit or prove revocation finished. Phone UI and configured-chain orchestration
are separate integrations.

The shared revocation call codecs are owned by `@oaath/protocol` and re-exported
through `@oaath/sdk/kernel`; invalid input reports `signing_request_invalid`.

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
