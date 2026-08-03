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

## Browser golden path

`createOAAth` is the one supported composition. Every deployment-owned
capability is injected: there is no preset system, no provider registry, and no
hidden network default.

```ts
import { createOAAth } from "@oaath/sdk";

const oaath = createOAAth({
  binding: { issuer, applicationId, applicationName, clientId, origin, redirectUri, deviceId, userHandle, account, operatorCredential },
  issuer: { url: issuer, fetch, signOut },   // your fetch carries the credentials
  authorization: { authorize },              // returns the code the owner released
  invalidation: { invalidateCapability },    // proves the approval capability is dead
  stores: { grants, operations, keys, cleanup, context },
  chains: [{ chainId, reads, observation, bundler, submission, quote, usage, feePayer }],
  signing: { owner, session },
  localKeyIds: ["session-key"],
  now: () => Math.floor(Date.now() / 1000),
});

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
store revisions, or nonce recovery. Persistence is explicit: pass the in-memory
backends or the IndexedDB ones from `openOaathDatabase`. IndexedDB keeps exactly
one current schema; a database that does not carry it is deleted and recreated
rather than migrated, and key custody stores only non-extractable `CryptoKey`
handles and exposes no export path.

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

Account descriptors are process-local evidence handles. After a process reload,
call `bindKernelV4Account` again before preparing another operation; serialized
or copied descriptors are deliberately rejected. A descriptor also freezes the
account state observed at bind time: after a counterfactual account's first
operation deploys it, rebind before preparing the next operation, or EntryPoint
rejects the stale factory evidence (`AA10 sender already constructed`).

Gas values are caller-supplied decimal strings. Gas and fee estimation is an
explicit non-goal of this package; bring values from your own estimation
source. `createKernelV4Reads` adapts any viem-style public client into the
account read capability, and `asViemUserOperation` maps a prepared operation
into viem's shape for signing and submission.

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

## License

Apache-2.0
