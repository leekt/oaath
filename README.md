# OAAth

OAAth is OAuth for scoped smart-account authority.

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

Kernel/ZeroDev is the opinionated first runtime. OAAth never depends on Moesi,
and it does not own deployment manifests, drift detection, deployment planning,
or desired-state convergence.

## Packages

| Package | Purpose |
| --- | --- |
| `@oaath/protocol` | Runtime-neutral wire and durable contracts. |
| `@oaath/sdk` | Browser client plus the concrete Kernel/ZeroDev runtime. |
| `@oaath/server` | Deployable relay and PostgreSQL boundary. |
| `@oaath/testing` | Deterministic fixtures and clean-consumer harnesses. |

All four publish together in one fixed `0.x.y` release group. The first release
is `0.1.0`; no package becomes `1.0.0` during this program.

[`native/ios`](native/ios/README.md) carries the experimental owner-phone
SwiftUI approval app (preview only): it is not part of the release group and is
never published to npm.

## Status

Nothing is released. `@oaath/protocol` owns the runtime-neutral wire and
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
and the experimental phone and APNs preview surfaces. Remaining capabilities land
as bounded, independently reviewed child PRs.

The wallet-RPC surface intentionally distinguishes finalized standards from
experiments:

| Surface | Standards status | OAAth status |
| --- | --- | --- |
| EIP-5792 `wallet_sendCalls` / status / capabilities | Final (`2.0.0`) | Implemented PoC path |
| ERC-7836 `wallet_prepareCalls` / `wallet_sendPreparedCalls` | Draft (`1`) | Experimental OAAth profile; opaque five-minute context, approved secp256k1 or WebAuthn operator, one-time durable consumption |
| ERC-7677 `paymasterService` | Review | Experimental `wallet_sendCalls` path for a deployment-registered same-service proxy and bundler estimator |
| ERC-7902 `staticPaymasterConfiguration` | Draft | Experimental bundled `wallet_sendCalls` path for one authenticated per-chain configuration commitment |

The Draft profiles are not advertised as stable or as generic conformance.
ERC-7677 sponsorship for prepared calls and the remaining ERC-7902 capability
fields remain later, independent work.

## Browser golden path

`createOAAth` is the one supported constructor, and the OAAth service URL is
the only deployment fact an application supplies. `connect()` bootstraps the
authenticated, versioned service context — client identity, the logical
account and owner credential, and the chains the service executes on — and
the SDK derives the rest locally: the origin, a registered same-origin
redirect target, a device identity, and a fresh session key. The application
never holds an owner signer and cannot choose a different account, owner, or
chain surface than the deployment registered.

```ts
import { createOAAth } from "@oaath/sdk";

const oaath = createOAAth({ url: process.env.OAATH_URL });
// Local development: createOAAth() connects to http://localhost:8787.

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
await operation.wait();
await oaath.disconnect(grant); // revoke, signOut, forgetLocal, close
```

Applications never handle permission ids, enable envelopes, operation journals,
store revisions, or nonce recovery. Persistence defaults to IndexedDB where it
exists and memory elsewhere; both stay overridable. IndexedDB keeps exactly
one current schema; a database that does not carry it is deleted and recreated
rather than migrated, and key custody stores only non-extractable `CryptoKey`
handles and exposes no export path.

Every port the URL mode composes — the issuer transport, the owner-decision
capability, the stores, the chain adapters, the signing profiles, the clock —
remains an optional injected override on the same constructor for
deterministic tests and custom deployments: pass a configuration carrying
`binding` and the SDK composes exactly what you injected, fetching nothing.

The root import carries only this workflow. Infrastructure lives behind
explicit subpaths: `@oaath/sdk/kernel` (the reviewed Kernel primitives, for
owner devices and audits), `@oaath/sdk/advanced` (custom-deployment ports and
the overridden composition), `@oaath/sdk/persistence` (IndexedDB adapters and
record contracts), and `@oaath/sdk/testing` (deterministic memory stores,
never a production dependency).

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

The only supported account runtime is Kernel v4 UUPS (`0.4.0`) through
EntryPoint `0.7`. OAAth currently recognizes the Kernel v4 deployment on
Arbitrum Sepolia, Ethereum Sepolia, and Robinhood Chain Testnet. It does not
retain Kernel 3.3 profiles or translate their permission representation.

`@oaath/sdk` owns the native Kernel v4 `Install[]`, validation nonce,
enable-signature, UUPS factory, and ERC-7579 execution encodings. The v0.7
KernelFactory at `0xE65C6a17bDB14070977b4AB70f1E7d9cDf441d53` is part of the
deployment profile and is accepted only after its `UUPS()` binding and the
EntryPoint, implementation, and factory runtime code hashes, plus the resulting
account implementation, match that profile.

Credential kinds are pluggable through one interface. `ecdsaKey`, `p256Key`, and
`webauthnKey` are `KeyProfile` implementations, and a consumer implements the same
interface to add a kind: `{ kind: "custom:<slug>", publicMaterial,
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

Authority is all-chain; evidence is not. The account state, Kernel's install
nonce, the EntryPoint nonce, the operation identity, the submission route, and
inclusion, finality and revocation evidence all stay chain-local, and no chain
borrows another's. There is no global atomic install, execute, or revoke.

Account descriptors are process-local evidence handles. After a process reload,
call `bindKernelV4Account` again before preparing another operation; serialized
or copied descriptors are deliberately rejected. A descriptor also freezes the
account state observed at bind time: after a counterfactual account's first
operation deploys it, rebind before preparing the next operation, or EntryPoint
rejects the stale factory evidence (`AA10 sender already constructed`).

Gas values in the low-level Kernel helpers are caller-supplied decimal strings;
bring them from your own estimation source. The experimental URL-mode ERC-7677
path makes one post-stub estimate through the deployment's registered bundler
port. `createKernelV4Reads` adapts any viem-style public client into the account
read capability, and `asViemUserOperation` maps a prepared operation into viem's
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
pnpm examples:check # all four; skips all-chain when Anvil is absent
```

They are documentation, not release evidence, and are deliberately not a CI gate;
the packed smokes below own that. Run them locally when a public surface changes.

## Before 0.1.0

The remaining release blockers have one durable ledger here:

- owner-authorized changeset for the fixed `0.x` release group;
- revocation send/return crash proof, including reload without resubmission;
- PostgreSQL as a default-gate persistence proof rather than an opt-in skip;
- pin or explicitly remove the unsupported `session_p256` / WebAuthn signer
  surface before release.

## Development

Requirements:

- Node.js 22.13 or newer
- pnpm 11.15.1

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm build
pnpm lint
pnpm --filter @oaath/sdk test:anvil # explicit local Kernel v4 / EntryPoint 0.7 proof
```

Automated tests must not contact paid or shared RPC services. Contract and
runtime integration tests use local Anvil unless a dedicated live-network suite
is explicitly opted into and bounded. Repository rules live in
[AGENTS.md](AGENTS.md).

## Packaging gates

These run in CI on every change and prove the published artifacts, not the
workspace:

```sh
pnpm check:public-surface # no node:/pg leakage into a browser graph; one-way deps
pnpm smoke:browser        # packed protocol + sdk + server, golden path, realm recreation
pnpm smoke:extension      # packed MV3 extension, forced worker death, durable status recovery
pnpm smoke:server         # packed server, relay round-trip, ./postgres under node
pnpm smoke:all-chain      # two local Anvil chains, one replayable owner approval
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

All four packages are one fixed `0.x.y` group and publish together. Publishing is
a manual, owner-authorized action; no workflow runs it.

```sh
pnpm changeset         # describe the change
pnpm release:status    # what would be released
pnpm release:version   # apply versions and changelogs
pnpm release:publish   # owner only: publish the fixed group and tag it
```

`release:publish` is plain `changeset publish`, so it publishes only what
`release:version` already committed and tags each published package. Set
`NPM_CONFIG_PROVENANCE=true` to attach npm provenance when publishing from a
trusted CI runner.

## License

Apache-2.0
