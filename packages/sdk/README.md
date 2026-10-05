# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

With service approvals, `requestPermission` accepts an optional
`onPending({ requestId, matchCode, expiresAt })` callback before waiting for the
owner. Display the eight-character code for comparison with the phone and clear
it when the request settles. `expiresAt` is in Unix milliseconds; the code is
non-secret display metadata and grants no authority. Wallet approvals do not
call this callback.

Service and wallet approvals share one optional `session` setting (`OaathSession`):
`session?: { kind?: "ecdsa" | "webauthn", custody?: "browser" | "application-backend" | "oaath-hosted", ... }`.
Omitted, the realm generates an ECDSA session key in the custody the deployment
declares. `session: { kind: "webauthn", ...webauthnKeyInput }` makes the owner
review and install the caller's passkey as the operator credential; no session
key is generated or stored.

The service bootstrap owns custody; `custody` never selects or overrides it. It
is a requirement: a declared custody that differs, a passkey under backend or
hosted custody, or remote custody under wallet approvals fails with
`oaath_client_capability_unsupported` (source `session_custody_unsupported`)
before any session key, store, or signer request exists.


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
`createKernelRuntime({ deployment: kernelAccountDeployment(account), reads,
operator: sessionOperator({ key: kernelKey(passkey), policies }) })` from
`@oaath/sdk/kernel`. The caller supplies the selected credential and authenticator
callback; the WebAuthn key checks its challenge, credential public key, RP ID, exact
HTTPS origin, user presence and verification before returning a signature.
Use the same `approveKernelPermission` / `materializeKernelPermission`
flow as ECDSA sessions. Root-owner binding remains ECDSA-only; the permission's
signer is independent of that root. This custom Kernel API does not replace
the application's durable operation journal or implement browser credential UI.
For approval and preparation with only public identity, use
`kernelKey({ credential })` in the session operator. It
derives the same permission as the matching signing profile and cannot sign.
For custom revocation of a permission, `prepareKernelPermissionRevocation`
(from `@oaath/sdk/kernel`) prepares the exact owner calls for the approval's
Kernel version, and `verifyKernelPermissionRevocation` proves removal at a
finalized canonical block. A successful operation receipt alone does not prove
removal.

## Owner operations

For an existing Kernel account, execute calls directly as its root owner. The
account's Kernel version (`0.3.3` or `0.4.0`) is detected onchain on each send and
reported as `review.kernelVersion`; no version is configured. Omitting
`approvals` gives owner-only execution, which needs no issuer, relay, Grant, or
enable approval:

```ts
import { createOAAth } from "@oaath/sdk";

// Plain descriptors: createOAAth builds the default viem chain ports.
const chains = { 143: { publicRpcUrls: [publicRpcUrl], bundlerUrl } };
const oaath = createOAAth({ chains, account: existingKernelAddress });
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

The operation journal defaults to `stores: { kind: "indexeddb" }`. Tests and
non-browser development choose `stores: { kind: "memory" }`, and any backend
accepts a durable journal adapter, e.g.
`stores: { kind: "memory", operations: postgresJournal }`; the client owns its
close. An unresolved operation occupies
one account/chain slot. Concurrent sends and sends after reload fail with a state
conflict until observation resolves it; `getOperation` only observes the exact
saved identity. Closing releases resources and does not revoke account authority.
The owner key is an optional setting: a connected viem wallet (the ECDSA
default) or any `kernelKey(...)` signing profile, such as a raw P-256 key
(`account.owner(kernelKey({ credential, sign }))`). The account stays at its
existing address. Each send checks its implementation, EntryPoint, root
validator and current owner. The root validator must expose its owner onchain:
the reviewed ECDSA validator, or on Kernel `0.4.0` the pinned raw P-256
validator. A WebAuthn owner key fails with `oaath_client_capability_unsupported`
(`source: "owner_key_kind_unsupported"`) before it signs. Owner-only execution uses the
bundler route by default. Applications can explicitly estimate a session before
selecting owner execution, as described below; OAAth never silently changes the
signer of an operation.

## Wallet-approved Grants

For scoped sessions without an issuer service or phone, add
`approvals: { kind: "wallet", owner }` to the same options. `owner` is a
browser or local viem wallet, which approves with one typed-data prompt, or any
`kernelKey(...)` signing profile the owner operations above accept, which signs
the same approval digest. The account's
Kernel deployment is detected on every configured chain; chains that disagree
fail with `local_account_deployment_mismatch`:

```ts
const oaath = createOAAth({
  chains,
  account: existingKernelAddress,
  approvals: {
    kind: "wallet",
    owner: walletClient,
    onApproval: async (review) => { await showPermissionPolicy(review.policy); },
  },
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
`approvals.onApproval` callback displays the decoded policy before the wallet prompt and
may throw to cancel. The SDK verifies
their root owner and matching permission nonce before prompting. The first send
enables the permission and executes its calls together. Reopening the same
origin/account/owner restores the session and operation journal; covered calls
then need no owner prompt. `resume()` can also return a revoked, expired, or
revoking Grant for observation or cleanup; only an active covering Grant may send.
Another permission request requires explicit wallet consent. No issuer network
request is made. Chain RPC and bundler calls still use the configured ports.

To sign wallet-approved sessions with a passkey instead of the generated key, pass
`session: { kind: "webauthn", credential, credentialId, rpId, origin, authenticate }`
(the WebAuthn `kernelKey` input). The passkey stays in its authenticator; only its public
credential is recorded in the Grant, and reopening with the same passkey resumes it.
The pinned WebAuthn signer verifies through the Daimo P-256 verifier contract, not
the RIP-7212 precompile, so approval fails closed with
`oaath_client_capability_unsupported` before any prompt on a chain without it.

Outside a browser, supply an explicit `origin` and a `stores` setting. The
default `{ kind: "indexeddb" }` fails with `oaath_client_store_unavailable`
where IndexedDB is missing; it never silently creates an ephemeral session.
`{ kind: "memory" }` runs without per-store wiring for tests and development,
but a restart forgets the session, Grant and operation IDs: a forgotten
operation is never resubmitted, and its calls must not be replayed blindly.
Individual stores can be overridden on either backend, e.g.
`{ kind: "memory", operations: postgresJournal }`, and
`{ kind: "indexeddb", factory, name }` selects the IndexedDB factory and
database. The same client also exposes
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
`auto` selects owner authority when the realm has a signer; service approvals' public-only
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
  bindKernelAccount, createKernelReads, createKernelRuntime, kernelAccountDeployment,
  kernelKey, ownerOperator,
} from "@oaath/sdk/kernel";

const reads = createKernelReads(publicClient);
// Detects the account's Kernel and EntryPoint versions onchain.
const existing = await bindKernelAccount({ chainId, address: existingKernelAddress, reads });
const runtime = createKernelRuntime({
  deployment: kernelAccountDeployment(existing),
  operator: ownerOperator({ key: kernelKey({ wallet: walletClient, validator: ecdsaValidator }) }),
  reads,
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
does not request accounts or retry a rejected signature. `ecdsaValidator` is
the account's root ECDSA validator module; it must support EIP-191, as the
reviewed ECDSA validator does. Passing `deployment` to `bindKernelAccount`, or
composing the runtime over another deployment, makes a mismatching account fail
with `kernel_runtime_deployment_mismatch` before anything is signed. Local accounts
using raw-hash signing can pass `kernelKey({ account, validator })` instead. On
Kernel 0.4.0, a P-256 `kernelKey({ credential, sign })` also binds an existing
account whose root validator is the pinned raw P-256 validator, whose stored
public key is readable onchain. Other root validators, including WebAuthn,
fail with `kernel_runtime_binding_mismatch`.
`sequence` is the current EntryPoint nonce sequence for this account and key;
`gas` contains canonical decimal strings. The low-level prepared-operation
schema calls its context label `grantId`; no Grant is created or needed here.
Preparation and signing do not submit. The caller must retain the prepared
operation and submission evidence using its chosen transport. An unavailable
read returns `kernel_runtime_read_unavailable`; it never creates an account or
selects a different Kernel version.

The lower-level runtime also supports ECDSA sessions on existing accounts. No
Kernel version is named; the approval follows the account's detected deployment:

```ts
import {
  approveKernelPermission, bindKernelAccount, createKernelReads, createKernelRuntime,
  kernelAccountDeployment, kernelKey, kernelPermissionNonce, materializeKernelPermission,
  sessionOperator,
} from "@oaath/sdk/kernel";

const reads = createKernelReads(publicClient);
const existing = await bindKernelAccount({ chainId, address: existingKernelAddress, reads });
const runtime = createKernelRuntime({
  deployment: kernelAccountDeployment(existing), reads,
  operator: sessionOperator({
    key: kernelKey({ account: sessionKey, validator: ecdsaValidator }),
    policies: [{ kind: "call", permissions: [{ target, selector, valueLimit: "0" }] }],
  }),
});
const account = await runtime.bindAccount({ address: existingKernelAddress });
const approval = await approveKernelPermission({
  runtime, account,
  owner: kernelKey({ wallet: walletClient, validator: ecdsaValidator }),
  nonce: await kernelPermissionNonce({ runtime, account, reads, requestHash }),
});
const { prepared, signature } = await materializeKernelPermission({
  runtime, account, approval, grantId: operationContextId,
  nonceKey: "0", sequence, calls, gas,
});
```

`kernelPermissionEnableTypedData({ runtime, account, nonce })` returns the exact
EIP-712 value for a wallet's `signTypedData` prompt instead. On a Kernel `0.3.3`
account the approval binds the account, effective validation nonce and exact
permission on every chain; `requestHash` is used only by Kernel `0.4.0`, where it
selects a fresh install key. Store the approval using its versioned
representation and restore with `parseKernelPermissionApproval`. Each destination must have the same effective
validation nonce; stale or mismatched state rejects rather than requesting another
signature silently. When Kernel `0.3.3` chains differ, take the highest
`kernelPermissionNonce` as the target and, on each lower chain, execute
`kernelPermissionNonceAlignmentCalls({ runtime, account, reads, nonce })` as one
owner operation. It installs and removes a throwaway permission that never
validates, never raises `validNonceFrom`, and leaves installed permissions
working; approvals signed for other permissions but not yet enabled on that
chain need a new nonce. The first operation enables and executes together; after confirmed installation, use the
same runtime's `prepareOperation` and `signOperation` in `standard` mode.
`encodeKernelNonceKey({ deployment, mode, validation, nonceKey })` (from
`@oaath/sdk/advanced`) derives the EntryPoint key for each mode; read that
key's sequence before preparing. Enable and standard mode have distinct keys.
Kernel v3.3's replayable enable uses an EIP-712 domain with `chainId: 0` and a
chain-zero session signing digest.
`kernelOperationSigningHash({ deployment, operation })` (also on `/advanced`)
returns the digest for an external session signer; `encodeVerifiedSignature` verifies that
digest. The stored prepared operation always retains its actual chain and
EntryPoint hash. Installed sessions and owner operations sign that actual hash.
The Monad enable gas floor applies before hashing or signing. Missing signer or
policy deployments prevent binding. These primitives prepare and sign only;
submission journaling and observation remain the caller's responsibility when
using them directly. A missing receipt never authorizes another send.
The approval schema is `oaath.kernel.v33-permission-approval/v2`; earlier
chain-bound approval records are rejected and must be recreated.

Custom issuer configurations can execute a v3.3 Grant using an account profile
with version `oaath.kernel-existing-account-profile/v3`, `kernelVersion: "0.3.3"`,
the existing `address`, EntryPoint version `0.7` (Kernel `0.3.3`) or `0.9` (Kernel v4), and its current ECDSA
`ownerCredential`. The issuer supplies a v3.3 approval beside the permission
decision and binds it with `kernelPermissionCapabilityHash(approval)`. The permission
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

`createOAAth` builds these default ports from plain `chains` descriptors
(`OaathChainDescriptor`) with the default request budget. To set the budget,
retries, or `fetch`, or to reuse the ports elsewhere, build them explicitly and
pass the array as `chains`; any `OaathChainCapability[]` is accepted the same
way as a custom override:

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

With `paymasterUrl`, the chain gets `sponsorship: { kind: "erc7677", url }`,
whose public service identity omits the query and trailing slash. Use that
identity in a requested `paymasterService` capability or a call's `payer.url`;
transport still calls the exact configured endpoint, including its query
parameters. A chain capability sets at most one optional `sponsorship`: either
`{ kind: "erc7677", url, request, estimate }` or `{ kind: "erc7902-static",
configurationHash }`, where the hash comes from
`hashErc7902StaticPaymasterConfiguration`. Omit it for no sponsorship.

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

Grant and owner reviews share one versioned contract,
`version: OAATH_CALLS_REVIEW_VERSION` (`oaath-calls-review-v1`). Its semantic
fields are closed enums: `signer`, `enforcement`, `validation`, and
`fallback.condition` / `fallback.feePayer`. A new value there is a new version.
Its identity fields are opaque, bounded strings: `account.implementation` (for
example `kernel:0.3.3`), `route` and `fallback.route`. A new Kernel version or
transport adds a value without changing `version`. Validate a review at your
trust boundary with `parseOaathCallsReview(review)`. It returns only the
contract fields. Any other version fails with
`oaath_client_review_version_unsupported`, and malformed or contradictory
fields fail with `oaath_client_input_invalid`. Check the semantic fields and
fingerprint the identity fields; do not enumerate them.

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
EntryPoint v0.7/v0.9 transaction by recomputing the operation hash, then decoding the
supported atomic Kernel execution. These are top-level requested calls; a
`reverted` outcome means their effects did not persist. Pending, dropped,
unreadable, mismatched, and unsupported evidence fails with a structured
`oaath_client_observation_unavailable` error. It never signs or sends.

Its `route` is the retained transport acknowledgement (`erc4337-bundler` or
`erc4337-handleops`), or `null` when the adapter did not report it or
observation won the acknowledgement race. A direct route is reported only when
its acknowledged transaction hash matches the verified inclusion transaction.
The acknowledgement alone never proves inclusion, finality, or permission to
resubmit. Custom submission sessions may return
`{ userOperationHash, submission: { route: "erc4337-bundler", transactionHash: null } }`
or `submission: { route: "erc4337-handleops", transactionHash }`; omit
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

Operation records now use `oaath.operation/v5`. Older records are rejected;
IndexedDB schema 16 recreates older local state without migration. This pre-1.0
reset deletes retained keys, Grants, and operation history, so applications must
reconnect and authorize fresh permissions. It does not revoke onchain authority.

Plain Grant and owner calls take one optional `payer` setting that says who pays
gas. Omit it and the account pays through the chain's configured routes. A
connected EOA can pay as a fallback:

```ts
const request = {
  chain,
  calls,
  payer: { kind: "connected-eoa", wallet: walletClient },
};
const review = await grant.reviewCalls(request); // initial route plus conditional fallback
const operation = await grant.sendCalls(request);
```

The initial route stays `erc4337-bundler`. A closed pre-acceptance rejection from the
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
evidence only from submission failures; service-approved clients capture it before
allowing the same local wallet fallback. Generic relay errors grant no fallback.

Custom observation transports answer `transaction_execution` with exactly
`{ hash, to, blockNumber, blockHash, input }` from the requested chain's
transaction. Addresses, hashes, and input are lowercase hex; blockNumber is a
canonical RPC hex quantity. The SDK reads input transiently and never returns
or persists its signatures. Existing operation state owns identity and finality;
this method adds no durable execution artifact.

Custom deployment quotes receive the selected Kernel `mode` and `validation`.
Choose a nonce namespace, encode its EntryPoint key with `@oaath/sdk/advanced`'s
`encodeKernelNonceKey({ deployment, mode, validation, nonceKey })`,
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
Both Grant and owner calls accept an explicit registered service as the payer:

```ts
const request = { chain, calls, payer: {
  kind: "paymaster-service", url: registeredPaymasterUrl,
  context: { policyId: "application-policy" },
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

`@oaath/sdk/kernel` exposes `prepareKernelPermissionApproval` for an owner
approval of a canonical permission request. It binds the request's account
using public credentials and configured reads, derives its policy packages
through `createKernelRuntime`, and returns the Kernel signing request. Where
the owner key lives is expressed only by who signs: `sign(ownerKey, decidedAt)`
takes one signature from a key profile, and `complete(artifact, decidedAt)`
verifies an owner device's P-256 signing artifact. Both return the permission
decision plus install approval consumed by the browser client. The caller owns
any device transport; the helper does not submit or persist anything. It
supports an existing Kernel `0.3.3` or `0.4.0` account whose ECDSA or raw P-256
root owner is proven onchain, a P-256 owner of a factory-derived Kernel `0.4.0`
account, and the current ECDSA/WebAuthn operator profiles. `reads` must serve
every supported deployment (`createKernelReads`). Any other request fails with
`kernel_runtime_unsupported` before signing, as does `complete` for a non-P-256
owner. Wallet-approved mode prepares its approval through the same owner.

Approval preparation derives its install nonce from
`hashPermissionRequest(request)`, as `kernelPermissionNonce` does: the first 192
hash bits select a request-specific Kernel install key at sequence zero. The
same request recreates the same signing packet, while different requests can
install in different orders across chains. This requires an unused key and
Kernel's global `validNonceFrom()` to remain zero on each destination chain;
accounts with an advanced global minimum require separate reconciliation.
The install nonce is separate from the EntryPoint operation nonce above.

For an untouched chain, `@oaath/sdk/advanced`'s
`encodeKernelInstallNonceInvalidationCall({ account,
installNonce })` encodes an owner self-call that advances that approval's key
to the next sequence. `encodeKernelInstallNonceRead({ key })` encodes the
account's `nonce(uint192)` read for checking its effective sequence. An already
consumed or invalidated nonce requires observation; repeating the self-call can
revert because Kernel requires an increase. Installed permissions still need
uninstall calls. These codecs do not submit, establish finality, or complete
configured-chain revocation.

`prepareKernelPermissionRevocation` prepares one owner revocation for any
supported Kernel version; the approval's `version` selects the semantics. For a
Kernel `0.4.0` approval it prepares one P-256 owner operation from
the canonical permission `request` and its retained install approval. Supply
the chain, root operation nonce, gas and the `effect` supported by chain
evidence: `invalidate-install` or `uninstall-permission`. For either version an
optional `paymaster` (EntryPoint 0.9 `address`, `verificationGasLimit`,
`postOpGasLimit`, `data`) sponsors the operation; it defaults to `null`
(self-funded) and is part of the hashed identity that restore reproduces. Retain its `prepared`
operation and `signingRequest` before requesting owner consent, and recreate it
with `restoreKernelPermissionRevocation({ preparation: signingRequest })`. The
signing request binds the workspace, application, install scope, chain,
EntryPoint and exact removal calls; it contains no enable signature.
`sign(ownerKey)` signs with a key profile, and `complete(artifact)` verifies an
owner device's artifact; both return the signature for that operation.
Preparation and signing never submit or prove revocation finished. Owner device
UI and configured-chain orchestration are separate integrations.

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
returns `capacity: { kind: "single-operation", detail }`. `detail` is
transport-specific and outside the review contract. Estimation includes any
explicitly selected sponsorship. It prompts and submits nothing, does not
reserve an operation slot, and fails when capacity cannot be established.
`sendCalls` obtains a fresh quote through the existing operation journal; a
review estimate is not an inclusion guarantee.
