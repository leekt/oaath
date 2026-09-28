# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

Existing Kernel `0.3.3` accounts support ECDSA owner operations through the
lower-level runtime. The account stays at its current address; its implementation,
EntryPoint, root validator and current ECDSA owner are checked before binding.
This path does not install permissions or change ownership. Kernel 3.3 Grant
permissions and high-level owner `sendCalls` are still pending.

```ts
import {
  createKernelRuntime, createKernelV33Reads, ecdsaWalletKey,
  kernelV33Deployment, ownerOperator,
} from "@oaath/sdk/kernel";

const deployment = kernelV33Deployment(chainId);
const runtime = createKernelRuntime({
  deployment,
  operator: ownerOperator({
    key: ecdsaWalletKey({ wallet: walletClient, validator: deployment.ecdsaValidator }),
  }),
  reads: createKernelV33Reads(publicClient),
});
const account = await runtime.bindAccount({ address: existingKernelAddress });
const prepared = runtime.prepareOperation({
  kind: "execution", grantId: operationContextId, account,
  nonceKey: "0", sequence, calls, gas,
});
const signature = await runtime.signOperation(prepared);
```

`walletClient` is a connected viem wallet client with an account. `ecdsaWalletKey`
requests one `personal_sign` signature over the exact 32-byte operation digest
and verifies the EIP-191 signature against that captured account locally. It
does not request accounts or retry a rejected signature. The validator must
support EIP-191, as the canonical Kernel v3.3 ECDSA validator does. Local accounts
using raw-hash signing can continue to use `ecdsaKey({ account, validator })`.
`sequence` is the current EntryPoint nonce sequence for this account and key;
`gas` contains canonical decimal strings. The low-level prepared-operation
schema calls its context label `grantId`; no Grant is created or needed here.
Preparation and signing do not submit. The caller must retain the prepared
operation and submission evidence using its chosen transport. An unavailable
read returns `kernel_runtime_read_unavailable`; it never creates an account or
selects a different Kernel version.

For Kernel v4 Grant execution, build the `chains` property of a custom
`createOAAth` configuration from RPC URLs:

```ts
import { createViemChainPorts } from "@oaath/sdk/viem";

const chains = createViemChainPorts({
  480: {
    publicRpcUrls: [publicRpcUrl, backupPublicRpcUrl],
    bundlerUrl,
    paymasterUrl, // optional registered ERC-7677 service
  },
}, {
  retry: { attempts: 3 },
  timeoutMs: 10_000,
  maxRequests: 1_000,
  maxConcurrency: 4,
});
```

Account reads, nonce, fees, finalized usage, and transaction/block evidence use
the public pool. Each endpoint must report the configured chain. The bundler
receives only ERC-4337 discovery, estimation, submission, and operation-receipt
calls; paymaster methods go only to `paymasterUrl`. Usage comes from the pinned
RateLimitPolicy at an exact finalized canonical block. An unavailable or absent
policy contract is not zero usage. RPCs must support `finalized` and EIP-1898
block-hash reads. The default quote uses nonce namespace zero and viem's fee
estimation. Existing gas-floor configuration can be supplied as `gas` per chain.

Read failures such as HTTP 429/5xx, invalid JSON, and timeouts retry within the
configured attempt count and fail over across public endpoints. Defaults are
three attempts, 100 ms between attempts, and a 10-second deadline per request.
Submissions, estimates, and paymaster stages make one attempt. A send timeout or
ambiguous response remains uncertain and is never resubmitted. The default
route uses the bundler, with no EOA fee payer or replacement-transaction indexer.

The shared lifetime budget counts chain checks and retries across all configured
chains; exhaustion throws `OaathRpcError` with `oaath_rpc_budget_exhausted`.
Concurrency above the limit fails with `oaath_rpc_concurrency_exceeded` rather
than queueing. Recreating ports explicitly starts a new budget; recover existing
operations for observation instead of repeating sends. Errors omit URLs,
provider prose, and request bodies. An optional `fetch(Request)` can supply an
application transport or local test fixture. Construction performs no I/O.

The public paymaster service identity at `chain.paymasterService.url` omits the
query and trailing slash. Use that identity in a requested `paymasterService`
capability; transport still calls the exact configured endpoint, including its
query parameters.

`grant.sendCalls({ chain, calls })` starts a new operation and returns its handle
without waiting for inclusion. Retain `{ chain: operation.chainId, id: operation.id }`
with the application's job. An unresolved operation occupies that grant/chain
lane, so another send fails with `oaath_client_state_conflict`.

`grant.reviewCalls({ chain, calls })` returns immutable current execution facts:
the public grant/account identities, captured calls, session signer, selected
submission route, policy validity window, operation limit, and actual onchain
enforcement. It checks the same scope, runtime, and account evidence as sending,
without quoting a nonce, signing, submitting, or writing Grant/Operation state.
Failures use `OaathClientError` codes. An unreadable bundler is reported in
`reasons` and stays on the bundler route; it never authorizes fallback. Review
is a snapshot, not a reservation or authorization: sending rechecks current
state, and applications should review again after relevant facts change.

After reconnecting and resuming the grant, `grant.getOperation({ chain, id })`
recovers that exact execution from local history, including terminal records
after a later operation replaces the lane. Lookup and observation do not quote,
sign, or submit, and work after grant expiry or revocation. `null` means no
matching retained record, never permission to retry a send.

`operation.execution()` reobserves that exact operation and returns immutable
finalized grant ID, sender, ordered calls, transaction/block identity, and success or
revert outcome. It checks the receipt and derives calls from the containing
EntryPoint v0.7 transaction by recomputing the operation hash, then decoding the
supported atomic Kernel execution. These are top-level requested calls; a
`reverted` outcome means their effects did not persist. Pending, dropped,
unreadable, mismatched, and unsupported evidence fails with a structured
`oaath_client_observation_unavailable` error. It never signs or sends.

Custom observation transports answer `transaction_execution` with exactly
`{ hash, to, blockNumber, blockHash, input }` from the requested chain's
transaction. Addresses, hashes, and input are lowercase hex; blockNumber is a
canonical RPC hex quantity. The SDK reads input transiently and never returns
or persists its signatures. Existing operation state owns identity and finality;
this method adds no durable execution artifact.

Custom deployment quotes receive the selected Kernel `mode` and `validation`.
Choose a nonce namespace, encode its EntryPoint key with `encodeKernelV4NonceKey`,
and read that key's sequence. The root, enable, and standard permission paths
have separate nonce domains; the SDK supplies the authority and the deployment
supplies its current chain sequence and gas.

Quotes also receive `simulation.prepared` and `simulation.signature`, built by
the same runtime as the final operation. They include the bound factory data,
call encoding, paymaster selection, and complete enable envelope when needed.
The simulation starts with nonce namespace and sequence zero, zero gas and fees,
and any applicable enable gas floor. For `purpose: "estimate"`, read the actual
nonce and fees before estimating. For `"sponsorship"`, read only the nonce and
fees: ERC-7677 estimates after obtaining paymaster stub data. For `"revalidate"`,
read only the nonce and keep the simulation's retained gas, fees, and paymaster
bytes. Return the selected namespace, sequence, and gas. Never submit or persist
this simulation. Its signature can contain the retained owner approval, so never
log it.

Usage ports receive `grantId`, `chainId`, `account`, `permissionId`, and
`maximumOperations` before quoting. Read finalized usage for that exact account
and permission; an unavailable read must remain unavailable, never a zero count.

Configure an enable gas floor on each chain capability when needed:

```ts
createOAAth({
  // Other existing client options...
  chains: [{ ...monadPorts, gas: { enableVerificationGasFloor: 2_000_000n } }],
});
```

Monad (143) defaults to `2_000_000n`; other chains default to zero. An explicit
nonnegative uint120 `bigint` overrides that default. The first session-enable
operation uses the greater of the quoted verification gas and this floor.
Owner operations and installed-session operations keep their quoted gas.
`grant.reviewCalls()` reports `enableVerificationGasFloor` as a decimal string,
or `null` when no floor applies, without quoting or reserving a nonce.
The lower-level `createKernelRuntime` accepts the same `gas` option.
Relay bootstrap preserves an explicitly configured floor.

ERC-7677 sponsorship applies the floor before requesting final paymaster data.
Custom sponsorship adapters receive `verificationGasFloor` with their prepared
candidate and must honor it before authorizing the final gas. A reply below the
floor is rejected before signing; its authorized fields are never changed after
the paymaster response. This policy does not retry failed validation or submission.

When a bundler supplies ABI-encoded EntryPoint `FailedOpWithRevert` data for
`AA23 reverted` with an empty inner revert, preparation errors and uncertain
submission outcomes expose `diagnostic.kind = "validation_gas_likely_insufficient"`
and the attempted `verificationGasLimit` as a decimal string. The message says
"likely validation out-of-gas"; it does not establish the cause. Provider RPC
errors preserve the fixed numeric message and expose the hint in `data.diagnostic`.
Message-only errors and nonempty reverts remain generic. The diagnostic is
ephemeral, does not authorize a retry, and does not release an unresolved lane.

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
