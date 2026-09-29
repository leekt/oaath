# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

In service URL mode, `requestPermission` accepts an optional
`onPending({ requestId, matchCode, expiresAt })` callback before waiting for the
owner. Display the eight-character code for comparison with the phone and clear
it when the request settles. `expiresAt` is in Unix milliseconds; the code is
non-secret display metadata and grants no authority. Local wallet mode does not
call this callback.

URL mode and local mode share one optional `session` setting (`OaathSession`).
`createOAAth({ url, session: { kind: "webauthn", ...webauthnKeyInput } })` makes
the owner review and install the caller's passkey as the operator credential; no
session key is generated or stored. A deployment that declares backend or hosted
session custody refuses it with `oaath_client_capability_unsupported`.


Custom Kernel sessions can set a fixed-window quota with
`{ kind: "rate-limit", intervalSeconds: "86400", maximumOperations: "25" }`
in `sessionOperator({ key, policies })`. Include a `call` profile; expiry and an
independent lifetime `operation-limit` can be included too. The quota belongs
to the onchain permission/account pair. Installation starts the first window;
the first validation after it ends replenishes the count and starts the next
interval. A validated operation consumes a slot even if execution reverts.
Reopening a runtime does not reset quota, and missing receipts still cannot
authorize resubmission.

The reset policy is pinned by `OAATH_KERNEL_RATE_LIMIT_POLICY` and
`OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH` from `@oaath/sdk/kernel`.
The matching module must already be deployed on the action chain; binding
fails with `kernel_runtime_policy_unavailable` for missing or different code.
The repository's `packages/sdk/test/fixtures/kernel-rate-limit-deployment.json`
contains the deterministic deployment input. Its complete Solidity input is
reproduced by `bun run --filter @oaath/sdk check:rate-limit-artifact`; bundled source
licenses are in that fixture directory's `licenses/` folder. This primitive is
available through the Kernel API; the default permission-request schema still
exposes its existing lifetime operation bound.

Existing Kernel `0.3.3` accounts also support custom passkey sessions through
`createKernelRuntime({ deployment: kernelV33Deployment(chainId), reads,
operator: sessionOperator({ key: kernelKey(passkey), policies }) })` from
`@oaath/sdk/kernel`. The caller supplies the selected credential and authenticator
callback; the WebAuthn key checks its challenge, credential public key, RP ID, exact
HTTPS origin, user presence and verification before returning a signature.
Use the same `approveKernelV33Permission` / `materializeKernelV33Permission`
flow as ECDSA sessions. Root-owner binding remains ECDSA-only; the permission's
signer is independent of that root. This custom Kernel API does not replace
the application's durable operation journal or implement browser credential UI.
For approval and preparation with only public identity, use
`kernelKey({ credential })` in the session operator. It
derives the same permission as the matching signing profile and cannot sign.
For custom revocation, `readKernelV33PermissionState` reads through the caller's
block-pinned `call` capability and `kernelV33PermissionRevocationCalls` prepares
the exact owner calls. Send all returned calls atomically. An unused approval
requires installation and removal to consume its permission nonce; an already
absent, invalidated approval returns no calls. Verify both permission absence
and `kernelV33EffectivePermissionNonce(state) > approval.nonce` at a finalized
canonical block. A successful operation receipt alone does not prove removal.

## Owner operations

For an existing ECDSA-root Kernel `0.3.3` account, execute calls directly with a
connected viem wallet. This mode needs no issuer, relay, Grant, or enable approval:

```ts
import { createOAAth } from "@oaath/sdk";
import { createViemChainPorts } from "@oaath/sdk/viem";

const oaath = createOAAth({ mode: "owner", chains: createViemChainPorts({
  143: { publicRpcUrls: [publicRpcUrl], bundlerUrl },
}) });
const account = oaath.account(existingKernelAddress);
const owner = account.owner(walletClient);
const calls = { chain: 143, calls: [{ target, value: "0", data }] };
const review = await owner.reviewCalls(calls); // estimates capacity; no prompt or submission
const operation = await owner.sendCalls(calls); // one personal_sign prompt, one UserOperation
await operation.wait();
// Retain operation.id; after recreating the client, recovery requires no wallet:
const saved = await account.getOperation({ chain: 143, id: operation.id });
await oaath.close();
```

The default operation journal uses IndexedDB. Custom deployments may inject an
`operations` adapter; the client owns its close. An unresolved operation occupies
one account/chain slot. Concurrent sends and sends after reload fail with a state
conflict until observation resolves it; `getOperation` only observes the exact
saved identity. Closing releases resources and does not revoke account authority.
The account stays at its existing address. Each send checks its implementation,
EntryPoint, root validator and current ECDSA owner. Owner mode currently uses the
bundler route by default. Applications can explicitly estimate a session before
selecting owner execution, as described below; OAAth never silently changes the
signer of an operation.

## Local wallet mode

For scoped sessions without an issuer service or phone, use local mode with the
same existing account and either a browser or local viem wallet:

```ts
const oaath = createOAAth({
  mode: "local",
  account: existingKernelAddress,
  owner: walletClient,
  chains: createViemChainPorts({ 143: { publicRpcUrls: [publicRpcUrl], bundlerUrl } }),
  onApproval: async (review) => { await showPermissionPolicy(review.policy); },
});
const connection = await oaath.connect();
const grant = await connection.resume() ?? await connection.requestPermission({
  chainScope: "all",
  permissions: [{ calls: [{ target, selectors: [selector], valueLimit: "0" }] }],
  expiresIn: 3600,
  perChainOperationLimit: 10,
});
const operation = await grant.sendCalls({ chain: 143, calls: [{ target, data, value: "0" }] });
await operation.wait();
await oaath.close();
```

`perChainOperationLimit: 10` is a lifetime cap on each chain. Pass
`{ count: 10, intervalSeconds: 86_400 }` for at most ten operations per chain per
day; the pinned rate-limit policy refills the quota once per fixed window, and a
validated operation uses a slot even when its execution reverts.

The session key is encrypted in IndexedDB before consent. One wallet EIP-712
approval covers the exact permission on all configured chains. The optional
`onApproval` callback displays the decoded policy before the wallet prompt and
may throw to cancel. The SDK verifies
their root owner and matching permission nonce before prompting. The first send
enables the permission and executes its calls together. Reopening the same
origin/account/owner restores the session and operation journal; covered calls
then need no owner prompt. `resume()` can also return a revoked, expired, or
revoking Grant for observation or cleanup; only an active covering Grant may send.
Another permission request requires explicit wallet consent. No issuer network
request is made. Chain RPC and bundler calls still use the configured ports.

To sign local sessions with a passkey instead of the generated key, pass
`session: { kind: "webauthn", credential, credentialId, rpId, origin, authenticate }`
(the WebAuthn `kernelKey` input). The passkey stays in its authenticator; only its public
credential is recorded in the Grant, and reopening with the same passkey resumes it.
The pinned WebAuthn signer verifies through the Daimo P-256 verifier contract, not
the RIP-7212 precompile, so approval fails closed with
`oaath_client_capability_unsupported` before any prompt on a chain without it.

Outside a browser, supply an explicit `origin` and durable `stores` through
`OaathLocalConfiguration`. Local mode fails if default IndexedDB is unavailable;
it does not silently create an ephemeral session. The same client also exposes
`oaath.account(existingKernelAddress).owner(walletClient)` and account-level
operation recovery. `close()` releases resources without revocation;
`disconnect(grant)` revokes installed or unused approval onchain, signs out
locally, and deletes local key custody only after revocation completes. Failed
cleanup remains retryable. Missing receipts never authorize another submission.

## Choosing a Grant signer

Existing Grant users may explicitly prefer the available owner:

```ts
const request = { chain: 143, calls: [{ target, value: "0", data }], signer: "auto" as const };
const review = await grant.reviewCalls(request); // chosen signer and structured reason
const operation = await grant.sendCalls(request);
```

Default sends (or `signer: "session"`) still use only the approved session.
`auto` selects owner authority when the realm has a signer; URL mode's public-only
owner profile selects session. Each accepted plain call bundle encodes one atomic
UserOperation. The API does not split oversized bundles, and an estimate, wallet
rejection or uncertain submission never changes the selected signer or retries.
Root execution does not enable the permission or consume its operation limit.
Its review reports no onchain Grant call/expiry/count enforcement and null policy
bounds; the client still requires an active, unexpired Grant. Owner approval of
the exact calls authorizes that wider root operation. For a one-off change with
no Grant approval at all, use the standalone owner mode above.

Owner and session sends share the Grant/chain operation lane. `getOperation`
recovers either signer without another signature or submission. Custom injected
signing configurations declare an available owner unless they provide a
public-only `kernelKey({ credential })`; a failed signer never becomes a session fallback.

## Runtime primitives

The same owner operation is available through the lower-level runtime:

```ts
import {
  createKernelRuntime, createKernelV33Reads, kernelKey,
  kernelV33Deployment, ownerOperator,
} from "@oaath/sdk/kernel";

const deployment = kernelV33Deployment(chainId);
const runtime = createKernelRuntime({
  deployment,
  operator: ownerOperator({
    key: kernelKey({ wallet: walletClient, validator: deployment.ecdsaValidator }),
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

`walletClient` is a connected viem wallet client with an account. A `wallet` key
requests one `personal_sign` signature over the exact 32-byte operation digest
and verifies the EIP-191 signature against that captured account locally. It
does not request accounts or retry a rejected signature. The validator must
support EIP-191, as the canonical Kernel v3.3 ECDSA validator does. Local accounts
using raw-hash signing can pass `kernelKey({ account, validator })` instead.
`sequence` is the current EntryPoint nonce sequence for this account and key;
`gas` contains canonical decimal strings. The low-level prepared-operation
schema calls its context label `grantId`; no Grant is created or needed here.
Preparation and signing do not submit. The caller must retain the prepared
operation and submission evidence using its chosen transport. An unavailable
read returns `kernel_runtime_read_unavailable`; it never creates an account or
selects a different Kernel version.

The lower-level runtime also supports ECDSA sessions on existing v3.3 accounts:

```ts
import {
  approveKernelV33Permission, createKernelRuntime, createKernelV33Reads,
  kernelKey, kernelV33Deployment,
  kernelV33PermissionInstallNonce, materializeKernelV33Permission, sessionOperator,
} from "@oaath/sdk/kernel";

const deployment = kernelV33Deployment(chainId);
const reads = createKernelV33Reads(publicClient);
const runtime = createKernelRuntime({
  deployment, reads,
  operator: sessionOperator({
    key: kernelKey({ account: sessionKey, validator: deployment.ecdsaValidator }),
    policies: [{ kind: "call", permissions: [{ target, selector, valueLimit: "0" }] }],
  }),
});
const account = await runtime.bindAccount({ address: existingKernelAddress });
const approval = await approveKernelV33Permission({
  runtime, account,
  owner: kernelKey({ wallet: walletClient, validator: deployment.ecdsaValidator }),
  nonce: await kernelV33PermissionInstallNonce({ runtime, account, reads }),
});
const { prepared, signature } = await materializeKernelV33Permission({
  runtime, account, approval, grantId: operationContextId,
  nonceKey: "0", sequence, calls, gas,
});
```

This approval binds the account, effective validation nonce and exact permission
on every chain. Store it using its versioned representation and restore with
`parseKernelV33PermissionApproval`. Each destination must have the same effective
validation nonce; stale or mismatched state rejects rather than requesting another
signature silently. The first operation enables and executes together; after confirmed installation, use the
same runtime's `prepareOperation` and `signOperation` in `standard` mode.
`encodeKernelV33NonceKey` derives the EntryPoint key for each mode; read that
key's sequence before preparing. Enable and standard mode have distinct keys.
Kernel v3.3's replayable enable uses an EIP-712 domain with `chainId: 0` and a
chain-zero session signing digest. `kernelV33OperationSigningHash` returns the
digest for an external session signer; `encodeVerifiedSignature` verifies that
digest. The stored prepared operation always retains its actual chain and
EntryPoint hash. Installed sessions and owner operations sign that actual hash.
The Monad enable gas floor applies before hashing or signing. Missing signer or
policy deployments prevent binding. These primitives prepare and sign only;
submission journaling and observation remain the caller's responsibility when
using them directly. A missing receipt never authorizes another send.
The approval schema is `oaath.kernel.v33-permission-approval/v2`; earlier
chain-bound approval records are rejected and must be recreated.

Custom issuer configurations can execute a v3.3 Grant using an account profile
with version `oaath.kernel-existing-account-profile/v1`, `kernelVersion: "0.3.3"`,
the existing `address`, EntryPoint version `0.7`, and its current ECDSA
`ownerCredential`. The issuer supplies a v3.3 approval beside the permission
decision and binds it with `kernelV33CapabilityHash(approval)`. The permission
packages must be derived from the exact approved policy and session credential.
`grant.sendCalls` then enables on first use and uses the installed session on
later calls, at the same address. It journals before signing; `resume` and
`getOperation` recover the original operation without resubmission after reload.
With the owner signer available, `grant.revoke()` removes installed permissions
and consumes unused approvals on the configured chains. An unused approval is
installed and removed atomically without application calls or global nonce
invalidation. Completion requires finalized permission absence and a consumed
enable nonce. An uncertain revocation remains `revoking` across reload and is
observed again without resubmission. Other permissions remain usable.
V3.3 external prepared-call signing, request-time validity attenuation, and phone
approval are not supported yet.

## Chain ports

For Kernel v4 or v3.3 Grant execution, build the `chains` property of a custom
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

`grant.reviewCalls({ chain, calls, estimate: true })` also estimates the exact
session operation and returns `validation: "estimated" | "account-rejected"`.
The default is `"not-estimated"`. Estimation writes no operation or permission
installation state and performs no signing or submission. `"account-rejected"`
requires a canonical EntryPoint account-validation rejection from the estimation
RPC; arbitrary error text, signature rejection, malformed responses and timeouts
cannot produce it. Other failures throw a structured client error. This option
currently requires the session signer, an unsponsored bundler route and no
installation in progress. If `signer: "auto"` selects the owner, `estimate: true`
returns `session_estimation_unavailable` without estimating or changing signers.
An application may offer owner execution after `"account-rejected"`, but must
review that signer choice before sending. This result never permits resending an
operation that was already submitted or whose acceptance is uncertain.

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

Its `route` is the retained transport acknowledgement (`bundler` or
`entrypoint-handleops`), or `null` when the adapter did not report it or
observation won the acknowledgement race. A direct route is reported only when
its acknowledged transaction hash matches the verified inclusion transaction.
The acknowledgement alone never proves inclusion, finality, or permission to
resubmit. Custom submission sessions may return
`{ userOperationHash, submission: { route: "bundler", transactionHash: null } }`
or `submission: { route: "entrypoint-handleops", transactionHash }`; omit
`submission` when the route is unknown.

For direct acknowledgements, default viem observation reads the retained
transaction from the public RPC and locates the exact EntryPoint event. Recovery
needs neither a wallet nor a bundler index. The observer still verifies the
receipt, transaction, canonical blocks, and finality; a missing event or a failed
outer transaction leaves the operation unresolved and never authorizes a send.
Finality uses the configured RPC's `finalized` tag and canonical blocks by
number. After verifying inclusion, the observer requires the finalized height
to cover it, rereads the canonical inclusion hash, and rebinds the finalized
anchor by number. This takes a fixed number of reads regardless of receipt age;
it does not walk every intervening parent. These are RPC-attested chain facts,
not local consensus verification. A missing finalized tag, changed hash, wrong
chain or head behind inclusion remains unresolved. Custom capabilities must
provide canonical-by-number evidence, never a block merely located by hash.
See the [Ethereum RPC block semantics](https://ethereum.github.io/execution-apis/api/methods/eth_getBlockByNumber/).
Custom observation adapters receive an optional
`transaction: { hash, entryPoint }` hint on `user_operation_receipt`. Receipt and
execution projection also pass the verified inclusion transaction as a hint.

Applications with their own operation journal can verify a saved public
UserOperation reference without constructing an OAAth Grant or Operation:

```ts
import { createUserOperationObserver } from "@oaath/sdk/advanced";
import { createViemChainPorts } from "@oaath/sdk/viem";

const [port] = createViemChainPorts({
  [chainId]: { publicRpcUrls: [rpcUrl], bundlerUrl },
}, { retry: { attempts: 1 }, timeoutMs: 8_000, maxRequests: 96 });
const observer = createUserOperationObserver(port.observation);
try {
  const result = await observer.observeReference({
    // Exact fields; lowercase addresses/hash and a canonical decimal nonce.
    reference: { chainId, entryPoint, account, nonce, userOperationHash },
    observedAt: Date.now(),
    timeoutMs: 25_000,
    // transactionHash: savedDirectTransactionHash, when already known
  });
  // result.status: pending | unreadable | finalized
} finally {
  await observer.close();
}
```

`parseUserOperationReference` from `@oaath/protocol` captures the same immutable
identity at an application's input boundary. Observation verifies the exact
EntryPoint event, sender, nonce, hash, containing transaction, canonical block
and finality through the same pipeline as OAAth operation recovery. An
`unreadable` result may retain a verified receipt when finality is unproven;
only `finalized` proves finality. Receipt logs are scoped to that operation and
include its terminal `UserOperationEvent`. This reader neither derives executed
calls nor verifies application postconditions. It owns no journal, never checks
for replacements, and cannot authorize retries or release an application lane.
Recreate it after reload using the saved reference; `close()` drains active
bounded observations and closes the supplied capability. A missing or unreadable
receipt leaves the saved identity unresolved.

Operation records now use `oaath.operation/v4`. Older records are rejected;
IndexedDB schema 15 recreates older local state without migration. This pre-1.0
reset deletes retained keys, Grants, and operation history, so applications must
reconnect and authorize fresh permissions. It does not revoke onchain authority.

Plain Grant and owner calls can explicitly use a connected EOA as a fallback:

```ts
const request = {
  chain,
  calls,
  feePayer: { kind: "connected-eoa", wallet: walletClient },
};
const review = await grant.reviewCalls(request); // initial route plus conditional fallback
const operation = await grant.sendCalls(request);
```

The initial route stays `bundler`. A closed pre-acceptance rejection from the
default RPC transport allows one wallet `eth_sendTransaction` carrying the exact
same signed operation through EntryPoint `handleOps`. The wallet must already be
connected to the requested chain and expose the captured EOA through
`eth_accounts`; the SDK neither connects nor switches it. The wallet approves
and funds the outer transaction. No second operation signature is requested.
Review reports the conditional fallback address without contacting the wallet.

Acceptance, timeouts, HTTP 502 responses, unknown RPC codes, and malformed
results never trigger fallback. HTTP status alone never proves rejection.
A late rejection after the submission
session closes cannot start it either. Wallet rejection or a lost response never
retries the transaction. Retain the operation ID and observe it. This option
cannot be combined with paymaster sponsorship, which remains on the bundler
route. Custom direct transports must preserve `OaathRpcError` conclusive
rejections from `@oaath/sdk/viem`. The relay forwards their closed rejection
evidence only from submission failures; URL-only clients capture it before
allowing the same local wallet fallback. Generic relay errors grant no fallback.

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
Both Grant and owner calls accept an explicit registered service:

```ts
const request = { chain, calls, paymasterService: {
  url: registeredPaymasterUrl, context: { policyId: "application-policy" },
} };
await grant.reviewCalls(request); // reports the selected URL; no sponsorship request
const operation = await grant.sendCalls(request); // owner.sendCalls accepts the same selection
```

The URL must exactly match that chain's registered service. The SDK requests stub
data, estimates, and obtains final data once each before signing the final
operation. An invalid or unavailable sponsor fails the request; it never selects
an unsponsored send. Sponsorship requires the bundler route. `reviewCalls`
reports `paymasterService: { url }` or `null` and does not contact the sponsor.

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


Owner `reviewCalls` estimates the complete call list as one UserOperation and
returns `capacity: { kind: "single-operation", gas }`. Estimation includes any
explicitly selected sponsorship. It prompts and submits nothing, does not
reserve an operation slot, and fails when capacity cannot be established.
`sendCalls` obtains a fresh quote through the existing operation journal; a
review estimate is not an inclusion guarantee.
