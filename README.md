# OAAth

OAAth is OAuth for scoped smart-account authority.

Existing ECDSA-root Kernel **0.3.3** accounts keep their current address;
no v4 migration or ownership transfer is required. Choose the workflow that
matches the application:

| Workflow | Constructor | Approval |
| --- | --- | --- |
| [Owner operation](packages/sdk/README.md#owner-operations) | `createOAAth({ chains, account })` | One wallet signature for one atomic UserOperation; no Grant or enable step. |
| [Wallet-approved Grant](packages/sdk/README.md#wallet-approved-grants) | `createOAAth({ chains, account, approvals: { kind: "wallet", owner } })` | One connected-wallet approval, then scoped session operations; no phone or relay. |
| [Phone service](#service-approvals) | `createOAAth({ approvals: { kind: "service", url } })` | The service selects the account and chains; its owner phone approves the Grant. |

Install from npm (`@oaath/cli` provides the `oaath` command):

```sh
npm install @oaath/sdk
npm install -D @oaath/cli   # optional: `npx oaath doctor --chain 143`
```

All three use one constructor; the optional `approvals` setting is the only
difference:

```ts
import { createOAAth } from "@oaath/sdk";

const chains = { 143: { publicRpcUrls: [rpcUrl], bundlerUrl } };
const oaath = createOAAth({
  chains,
  account: existingKernelAddress,
  approvals: { kind: "wallet", owner: walletClient },
});
// Owner-only execution: omit `approvals`, then
//   oaath.account(existingKernelAddress).owner(walletClient).sendCalls(...)
// Phone service: createOAAth({ approvals: { kind: "service", url } });
//   the service supplies the account and chains.

const connection = await oaath.connect();
const grant =
  (await connection.resume()) ??
  (await connection.requestPermission({
    chainScope: "all",
    permissions: [{ calls: [{ target, selectors, valueLimit: "0" }] }],
    expiresIn: 1800,
    perChainOperationLimit: 10,
  }));
const operation = await grant.sendCalls({ chain: 143, calls });
await operation.wait();
```

Owner-only execution and wallet approvals use an existing ECDSA-owned Kernel v3.3 or v4 account;
the SDK detects its deployment. The phone
service uses Kernel v4 with a P-256 owner. All paths retain exact operation
identity for observation after reload. Before adopting a chain, check its
[runtime readiness](#kernel-runtime); the six-chain production v4 rollout is
still deferred.

The personal or team-operated phone service uses this model:

| Entity | Owns |
| --- | --- |
| Workspace | Personal or team membership and account selection. |
| Account | The Kernel account profile, configured chains, and enrolled owner phone. |
| Owner device | Consent and owner signatures for grants and onchain revocation. |
| Grant | One application's authority over one account, with explicit limits and expiry. |
| Job | Application intent executed as separately tracked chain-local operations. |

Workspace membership selects service context; it does not confer the phone's
signing authority. Job completion and grant revocation are separate from
workspace membership and application authentication. Limits must state their
unit and whether they apply per call, per chain, or across chains; the current
policy supports per-call native value and per-chain operation counts, not
aggregate token budgets across chains.

OAAth owns the complete smart-account authorization journey:

```text
connect application
→ bind client, origin, user, device, and logical account
→ request scoped all-chain authority
→ approve or reject
→ materialize permission on a supported chain when needed
→ choose the safe authority signer and submission route
→ prepare and durably bind the exact operation identity
→ submit
→ observe, recover, and finalize without resubmission
→ revoke authority
```

Kernel/ZeroDev is the opinionated first runtime. OAAth never depends on Moesi.
The CLI deploys OAAth's pinned runtime contracts. Application deployment
manifests, drift detection and desired-state convergence remain the consumer's
responsibility.

## Packages

| Package | Purpose |
| --- | --- |
| `@oaath/protocol` | IO-free wire, durable contracts, and Kernel v4 signing profiles. |
| `@oaath/sdk` | Browser client plus the concrete Kernel/ZeroDev runtime. |
| `@oaath/server` | Deployable relay and PostgreSQL boundary. |
| `@oaath/testing` | Deterministic fixtures and clean-consumer harnesses. |
| `oaath` | Node CLI: runtime readiness, deployment planning and deterministic deployment. |

All five use one fixed `0.x.y` release group. The current source is versioned
`0.3.4`, following the initial `0.1.0` proof of concept; no package becomes
`1.0.0` during this program. Versioned source does not imply npm publication.

## Status

The fixed package group is versioned for the next proof-of-concept release,
`0.3.4`. `@oaath/protocol` owns the shared wire and
durable contracts: grants, grant policies, identity profiles, the pure
`Operation` aggregate, the permission protocol, and the exact hostile-input
capture primitives. `@oaath/sdk` carries the runtime safety kernel on top of
it: durable store contracts, the canonical observer, the runner, and the
Kernel v4 runtime, and the browser client that composes them into
`createOAAth`. It captures one exact chain-local UserOperation identity,
records submission before an external send, and advances only from stronger
evidence. Missing receipts, timeouts, and unreadable observations never
authorize another submission or prove an operation dropped. `@oaath/testing`
carries the concrete SQLite test stores and is never a production dependency.
`@oaath/server` carries the durable authorization relay, its PostgreSQL store,
and the experimental phone and APNs preview surfaces.

The [phone service workflow](examples/phone/README.md) proves personal and team
account selection, approval by a simulated P-256 owner phone, bounded application jobs,
saved-operation recovery, and revocation across two configured local chains.
Its PostgreSQL scenario recreates the service and pools while retaining the
external chain backends; pending consent and submitted operation evidence
survive without another send. Swift host tests separately prove native consent
and signing. These gates do not prove a physical-device or hosted deployment.

The product model and this PoC workflow are implemented. Further decomposition
of the client, separating the wallet-RPC layer used by the extension, and native
release packaging remain follow-ups. They do not require a rewrite of the
Kernel runtime or operation state machine.

The wallet-RPC surface intentionally distinguishes finalized standards from
experiments:

| Surface | Standards status | OAAth status |
| --- | --- | --- |
| EIP-5792 `wallet_sendCalls` / status / capabilities | Final (`2.0.0`) | Implemented PoC path |
| ERC-7836 `wallet_prepareCalls` / `wallet_sendPreparedCalls` | Draft (`1`) | Experimental OAAth profile; approved secp256k1 external signer in `frontend` or `application_backend` custody, or approved WebAuthn external signer in `frontend` custody; current-version opaque five-minute context, one-time durable consumption and reload recovery; `oaath_hosted` custody is rejected |
| ERC-7677 `paymasterService` | Review | Experimental `wallet_sendCalls` and prepared-call paths for a deployment-registered same-service proxy and bundler estimator |
| ERC-7902 `staticPaymasterConfiguration` | Draft | Experimental bundled `wallet_sendCalls` path for one authenticated per-chain configuration commitment |
| ERC-7902 `validityTimeRange` | Draft | Experimental `wallet_sendCalls` and prepared-call paths only with a configured transaction confirmer and proof of the configured chain's pinned OAAth validity-policy runtime; `validAfter` and `validUntil` are inclusive |

The Draft profiles are not advertised as stable or as generic conformance.
ERC-7902 `multiDimensionalNonce`, AA gas parameter overrides, and
`eip7702Auth` are explicitly unsupported and deferred.

## Service approvals

With `approvals: { kind: "service", url }`, the OAAth service URL is the only
deployment fact an application supplies to `createOAAth`. `connect()` bootstraps the
authenticated, versioned service context — client identity, selected workspace, the logical
account and owner credential, and the chains the service executes on — and
the SDK derives the rest locally: the origin, a registered same-origin
redirect target, a device identity, and a fresh session key. The application
never holds an owner signer and cannot choose a different account, owner, or
chain surface than the deployment registered.

The relay calls `bootstrap.resolve(caller)` on every authenticated bootstrap
request. `createServiceDirectory(store)` resolves stored membership and account
selection into `{ application, context, account, ownerValidator, chainIds }`;
`null` means no assigned account. The relay derives the client ID, redirect
URIs, and user handle from authentication, and advertises only selected chains
with configured ports. `context` carries version
`oaath.workspace-account-context/v1`, `workspaceId`, `workspaceKind`
(`personal` or `team`), and `accountId`. A new connection fetches the current
selection; existing connections retain their captured context.

The permission request carries that context through owner review and binds it
into the request hash. Resuming a grant checks the stored request against the
connection's context. `oaath.permission-request/v2` is the only accepted request
schema; prior requests require fresh authorization.

Local sessions and grant lookup are isolated by authenticated caller,
workspace, and complete account profile. Switching contexts creates a distinct
realm; switching back can resume its prior session. The service directory owns
versioned workspace, application, membership, account, owner-device reference,
and selection records, with memory and PostgreSQL stores. Membership removal
blocks subsequent bootstrap resolution and request admission; it does not revoke
existing grants. The directory also resolves each permission request to the
registered account's owner device, checking its explicit context and account
profile rather than the current selection preference. After deployment-authenticated
pairing, `enrollOwnerDevice` registers a phone and its new P-256 accounts in one
directory write. The [reference phone service](examples/phone) uses this directory,
canonical native permission approval, and the URL SDK for personal/team jobs,
saved-operation recovery and revocation across two configured local chains.
Account selection UI remains deployment-owned.

```ts
import { createOAAth } from "@oaath/sdk";

const oaath = createOAAth({ approvals: { kind: "service", url: process.env.OAATH_URL } });
// Local development: omitting `url` connects to http://localhost:8787.

const connection = await oaath.connect();
const grant =
  (await connection.resume()) ??
  (await connection.requestPermission({
    chainScope: "all",
    permissions: [{ calls: [{ target, selectors, valueLimit: "0" }] }],
    expiresIn: 1800,
    perChainOperationLimit: 10,
  }));

const operation = await grant.sendCalls({ chain, calls });
// Keep { chain: operation.chainId, id: operation.id } with the application's job.
await operation.wait();
await oaath.disconnect(grant); // revoke, signOut, forgetLocal, close
```

`sendCalls` starts a new operation. One unresolved operation occupies each
grant/chain lane; another send returns `oaath_client_state_conflict`.
Independent jobs can reserve their own lane with
`sendCalls({ chain, calls, lane: { id: "run_01", nonceKey: 17n } })`. OAAth
never allocates lanes. The key must be one the runtime can represent (Kernel:
1 to 65535), and a lane is refused until the default lane has installed the
permission on that chain. `revoke()` does not complete while any lane has an
unresolved operation.
After reload, resume the grant and call `grant.getOperation({ chain, id })`
with the saved reference, adding the same `lane` for a laned operation. Its `observe()` and `wait()` methods submit nothing
and remain available after grant expiry or revocation. A missing local record
returns `null`; it is not evidence that the operation was never submitted.

Applications never handle permission ids, enable envelopes, operation journals,
store revisions, or nonce recovery. Persistence is one `stores` setting:
`{ kind: "indexeddb" }` by default, which fails closed where IndexedDB is
missing, or an explicit `{ kind: "memory" }`, with optional per-store adapter
overrides. IndexedDB keeps exactly
one current schema; a database that does not carry it is deleted and recreated
rather than migrated, and key custody stores only non-extractable `CryptoKey`
handles and exposes no export path.

Every port service approvals compose — the issuer transport, the owner-decision
capability, the stores, the chain adapters, the signing profiles, the clock —
remains an optional injected override on the same constructor for
deterministic tests and custom deployments: pass a configuration carrying
`binding` and the SDK composes exactly what you injected, fetching nothing.

The root import carries only this workflow. Infrastructure lives behind
explicit subpaths: `@oaath/sdk/kernel` (the version-agnostic Kernel primitives,
for owner devices and audits; Kernel and EntryPoint versions are optional
settings), `@oaath/sdk/advanced` (custom-deployment ports, version-named Kernel
encoders and deployment constants, and the overridden composition), `@oaath/sdk/persistence` (`openIndexedDbStores`,
the full IndexedDB store set, and record contracts), and `@oaath/sdk/testing`
(`createMemoryStores`, the deterministic memory store set, never a production
dependency). Both serve the overridden composition; `createOAAth` options
name a backend in `stores` instead.

For viem-based applications, `@oaath/sdk/viem` exposes an active Grant as a
narrow EIP-1193 provider — `eth_accounts` answers the chain-read-derived smart
account and `eth_sendTransaction` rides `grant.sendCalls` and returns the real
inclusion transaction hash — so existing viem code executes through OAAth
without learning its vocabulary:

```ts
import { createWalletClient, custom } from "viem";
import { oaathProvider } from "@oaath/sdk/viem";

const wallet = createWalletClient({
  transport: custom(oaathProvider({ grant, chain })),
});
const hash = await wallet.sendTransaction({ account, to, value, data, chain: null });
```

## Kernel runtime

The Grant workflow uses Kernel v4 UUPS (`0.4.0`) through EntryPoint `0.9`.
Existing ECDSA-root Kernel `0.3.3` accounts support
`createOAAth({ chains, account }).account(address).owner(walletClient).sendCalls(...)`.
It prompts once, creates no Grant, and uses the existing address with no enable
approval. IndexedDB retains exact operations for wallet-free `getOperation`
recovery. See the [SDK example](packages/sdk/README.md), including the lower-level
`createKernelRuntime` path. Existing v3.3 accounts also support session Grants through
`createOAAth({ chains, account, approvals: { kind: "wallet", owner: walletClient } })`,
with one wallet typed-data approval, browser custody and reload recovery.
Wallet approvals need no phone or relay. Explicit Grant `signer: "auto"` prefers an
available owner for the atomic call bundle; execution review identifies that
choice and its wider authority before signing.

The v4 runtime pins [Kernel PR #152](https://github.com/zerodevapp/kernel/pull/152),
merged at `c960b42d2ed4adb0d5328f6e762962debdf8e57a`. The upstream PR identifies
its production sources and compiler configuration as identical to the audited
revision; the audit report's publication remains upstream work. OAAth builds
that source with its pinned Solidity 0.8.33 profile and EntryPoint **0.9**
constructor binding. Local integration tests prove that EntryPoint path.

Validator install data now contains only packed selectors; signer install data
contains the permission ID followed by selectors. The old inline `hook` encoder
argument and generic module type 4 are rejected; scoped execution hooks use
module type 11. The constructor, runtime artifacts and CREATE2 addresses change.
Prior v4 deployments and grants are unsupported and require fresh setup; existing
Kernel 0.3.3 accounts keep their separate deployment profile.

The deployment profile has the same CREATE2 addresses on every chain.
`bindKernelAccount` checks the factory runtime hash and the factory's
implementation binding. Every chain requires code at the canonical EntryPoint and implementation
address; Kernel's chain-dependent runtime hash is not checked. There is no
per-chain implementation hash table. These checks do not claim that the new
contracts have already been deployed on any public chain.

To reproduce the retained artifacts from a clean checkout of the pinned Kernel
revision (including its committed dependencies):

```sh
bun run --filter @oaath/contracts kernel:check /path/to/kernel
# Update artifacts after an intentional pin change:
# bun run --filter @oaath/contracts kernel:generate /path/to/kernel
```

Check the runtime before integrating a chain:

```sh
npx @oaath/cli doctor --chain 143
npx @oaath/cli doctor --chain 143 --rpc https://rpc.monad.xyz --json
npx @oaath/cli deploy-runtime --chain 143 --rpc https://rpc.monad.xyz --dry-run
```

`@oaath/cli` installs the `oaath` command and is part of the fixed package
release group. From a repository checkout, run `bun run --filter @oaath/cli build`
then `node packages/cli/dist/cli.mjs doctor --chain 143`.
See [CLI usage](packages/cli/README.md) for bounds, exit codes and evidence limits.
`doctor` checks the ECDSA session module set; the owner validator remains
application-selected. It sends no transactions and never treats an unreadable
RPC response as a missing contract.
`deploy-runtime` checks EntryPoint and the singleton deployer, deploys only the
missing deterministic core set, and retains an attempt journal before broadcast.
See the CLI instructions for the funded-wallet environment variable and recovery;
an uncertain transaction is observed, never automatically resent.

Public runtime readiness has not been rechecked for this contract revision.
The previous six-chain snapshot described the retired artifacts. Run `doctor`
for fresh evidence; production deployment writes remain deferred.

`@oaath/sdk` owns the native Kernel v4 `Install[]`, validation nonce,
enable-signature, UUPS factory, and ERC-7579 execution encodings. The current
EntryPoint 0.9 factory is `0x3d6d678742e276b6388fd06c1b8ecd19e2d64c2d`; its
UUPS implementation is `0x6250926dd0309d9deaaeb4a2c413da5f3c4de37a`.

Credential kinds are pluggable through one interface. `kernelKey({ kind?, ... })`
returns the reviewed ECDSA, P-256 or WebAuthn `KeyProfile`, choosing the signing
source from the input it is given, and a consumer implements the same interface
to add a kind: `{ kind: "custom:<slug>", publicMaterial,
resolveValidator, signerModule, dummySignature, sign, verify }` composes through
`ownerOperator` and `sessionOperator` into the one `createKernelRuntime`, with no
credential-specific runtime. A custom kind resolves no pinned module, so it binds
its own ERC-7579 validator and permission signer module (`moduleType` 6). Both are
proven to carry code on the action chain when this runtime binds the account —
before the account address depends on them. The permission ID is derived locally
before any chain read, and a descriptor bound by a different runtime skips this
runtime's code proof; either way a codeless module fails closed at Kernel's
on-chain validation rather than granting anything. Sessions stay permission-scoped: at least one
policy is required for every kind. A produced signature must verify against the
profile's own bound public material before it is wrapped in any authority
envelope, and a reviewed kind may never bind its own signer module.

A raw P-256 credential — an Apple Secure Enclave key, for instance — holds root
owner authority through a pinned reviewed validator module, and its session keys
are ECDSA because no reviewed raw P-256 permission signer exists. That validator
verifies through the RIP-7212 / EIP-7951 precompile and has no Solidity fallback,
so it can only be deployed on a chain that carries the precompile; on a chain that
does not, the pinned address holds no code and `bindAccount` fails closed with
`kernel_runtime_validator_unavailable` before any account address depends on it.

### All-chain authority

`chainScope: "all"` is one owner approval, not one approval per chain. Every
module and account address in the runtime is CREATE2-derived, so one set of
initial packages yields one account address on every supported chain. The owner
signs Kernel v4's replayable enable digest once — a digest whose EIP-712 domain
omits the chain id and binds only the account, Kernel's install nonce and the
exact install packages — and `materializeKernelPermission` spends that one
signature on each chain the session first touches, including a chain that was not
configured when the owner approved. The session's first operation on a chain
carries the enable envelope; every later one is an ordinary standard-mode
operation against the installed permission.

Approval preparation selects a request-specific install nonce namespace,
so different grants can install in different orders on different chains. The
SDK starts each namespace at sequence zero: its key must be unused and Kernel's
global `validNonceFrom()` must still be zero on the destination chain. Advancing
that global minimum requires separate account reconciliation.

Authority is all-chain; evidence is not. The account state, Kernel's install
nonce, the EntryPoint nonce, the operation identity, the submission route, and
inclusion, finality and revocation evidence all stay chain-local, and no chain
borrows another's. There is no global atomic install, execute, or revoke.

Revocation snapshots the client's configured chains and any previously bound
chains. `revoked` requires finalized permission absence and a consumed approval
install nonce on every chain in that snapshot, including unused chains. Relay
invalidation stops service admission; it does not invalidate the owner signature
onchain. A missing chain transport leaves the Grant `revoking`, even after reload.
Service-approved `grant.revoke()` requests durable phone custody for every target still
missing proof. Repeated calls recover the current request; phone approval alone
leaves the Grant `revoking`. The deployment supplies chain preparation, phone
delivery and an execution worker, while the client observes the resulting effects.
Chains outside this snapshot are not covered by its revocation status.

Account descriptors are process-local evidence handles. After a process reload,
call `bindKernelAccount` again before preparing another operation; serialized
or copied descriptors are deliberately rejected. A descriptor also freezes the
account state observed at bind time: after a counterfactual account's first
operation deploys it, rebind before preparing the next operation, or EntryPoint
rejects the stale factory evidence (`AA10 sender already constructed`).

Gas values in the low-level Kernel helpers are caller-supplied decimal strings;
bring them from your own estimation source. The experimental service-approved ERC-7677
path makes one post-stub estimate through the deployment's registered bundler
port. `createKernelReads` adapts any viem-style public client into the account
read capability for every supported deployment, and `asViemUserOperation` maps a prepared operation into viem's
shape for signing and submission.

## Examples

Four runnable, narrated examples live in [examples/](examples). They import the
published specifiers only.

| Example | Shows |
| --- | --- |
| `examples/browser` | connect → one all-chain grant → execute → revoke, against injected chain facts or a real local chain |
| `examples/server` | the Fetch relay over `node:http`, PostgreSQL, and the auth and KMS ports a deployment owns |
| `examples/phone` | pair a real iPhone ([native/ios/Demo](native/ios/Demo)), APNs push, full consent screen, approve, one-time code delivery |
| `examples/all-chain` | one owner approval, chain B introduced afterwards, the same signature materialized on it |

```sh
bun run examples:check # all four; skips all-chain when Anvil is absent
```

They are documentation, not release evidence, and are deliberately not a CI gate;
the packed smokes below own that. Run them locally when a public surface changes.

## Development

Requirements:

- Node.js 22.13 or newer
- Bun 1.4.2 (pinned in `package.json`)

Bun manages the workspace, lockfile, and script execution. Use `bun run test`
and `bun run build` to run the existing Vitest/Forge and tsdown scripts. Node
remains required for tooling and the published Node consumer checks.
Workspace typechecking, tests, and examples opt into `oaath-source`; ordinary
package imports resolve the built `dist` exports.

```sh
bun install
bun run typecheck
bun run test
bun run build
bun run lint
bun run --filter @oaath/sdk test:anvil # explicit local Kernel v4 / EntryPoint 0.9 proof
```

Automated tests must not contact paid or shared RPC services. Contract and
runtime integration tests use local Anvil unless a dedicated live-network suite
is explicitly opted into and bounded. Repository rules live in
[AGENTS.md](AGENTS.md).

## Packaging gates

These run in CI on every change and prove the published artifacts, not the
workspace:

```sh
bun run check:public-surface # no node:/pg leakage into a browser graph; one-way deps
bun run smoke:browser        # packed protocol + sdk + server, golden path, realm recreation
bun run smoke:extension      # packed MV3 extension, forced worker death, durable status recovery
bun run smoke:server         # packed server, relay round-trip, ./postgres under node
bun run smoke:all-chain      # two local Anvil chains, one replayable owner approval
```

The browser, extension, and server smokes build, pack, and `npm install` the
tarballs into a throwaway consumer outside the workspace, so nothing resolves
through a workspace link and no `src` path is reachable. `smoke:extension`
loads the actual example artifact in headful Chrome, kills its MV3 worker, and
requires a distinct worker lifetime to recover the same IndexedDB-backed bundle
without resubmission; it uses only a loopback relay and an owned chain fixture.
CI supplies Xvfb; a local run requires Google Chrome.
`smoke:all-chain` runs the two-chain materialization proof with
`OAATH_REQUIRE_ANVIL` set, so it can never report an all-chain proof that skipped
itself.

## Release

All five packages are one fixed `0.x.y` group and publish together. Publishing is
a manual, owner-authorized action; no workflow runs it.

```sh
bun run changeset         # describe the change
bun run release:status    # what would be released
bun run release:version   # apply versions and changelogs
bun run release:check     # pack every public package; no publishing or tags
bun run release:publish   # owner only: publish the fixed group and tag it
```

Publish only from `main` after the versioning PR has merged; `release:publish`
publishes whatever versions the checkout carries. npm two-factor prompts need an
interactive terminal, and each package asks for its own confirmation.

Changesets owns versions, changelogs, and tags; `release:version` also refreshes
`bun.lock`. `release:publish` uses Bun to pack and publish the fixed group, resolving
workspace dependencies to concrete versions. Existing published versions are
tolerated so a partial release can be resumed; tags are created only after all
packages succeed. Every public package rebuilds its ignored `dist` during
`prepack`, so a clean-checkout publish cannot omit or reuse generated exports.

## License

Apache-2.0, including the OAAth-owned validity policy source and its embedded
SDK/CLI bytecode (owner decision for 0.3.1, #344). The policy declares the
[CC0 ERC-4337 packed ABI](https://eips.ethereum.org/EIPS/eip-4337#entrypoint-interface)
locally and imports no GPL implementation. Third-party contracts and their
artifacts retain their upstream licenses.
