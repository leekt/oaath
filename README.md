# OGP

OGP is OAuth for scoped smart-account authority.

The project is being rebuilt as a focused public package. Its first runtime is
Kernel/ZeroDev, and its canonical package name is `@leekt/ogp`.

OGP owns the authority and execution lifecycle:

```text
connect
→ request scoped all-chain authority
→ approve or reject
→ materialize a chain-local permission when needed
→ prepare an exact operation identity
→ submit once
→ observe or recover without resubmission
→ revoke
```

Moesi and other products consume OGP through released packages or exact local
tarballs. OGP never depends on Moesi.

## Status

The package is not released. The repository is landing the safety kernel in
bounded, independently reviewed changes before `@leekt/ogp@0.1.0` is
authorized for publication.

The first public unit is the pure `Operation` aggregate. It captures one exact
chain-local UserOperation identity, records submission before an external send,
and advances only from stronger evidence. Missing receipts, timeouts, and
unreadable observations never authorize another submission or prove an
operation dropped.

The aggregate deliberately does not submit or observe RPC operations. Durable
storage, the canonical observer, and the Kernel runtime land as separate,
independently reviewed units.

## Kernel runtime

The only supported account runtime is Kernel v4 UUPS (`0.4.0`) through
EntryPoint `0.7`. OGP currently recognizes the Kernel v4 deployment on Arbitrum
Sepolia, Ethereum Sepolia, and Robinhood Chain Testnet. It does not retain
Kernel 3.3 profiles or translate their permission representation.

The package owns the native Kernel v4 `Install[]`, validation nonce,
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
pnpm check
pnpm test:anvil # explicit local Kernel v4 / EntryPoint 0.7 proof
```

Automated tests must not contact paid or shared RPC services. Contract and
runtime integration tests use local Anvil unless a dedicated live-network suite
is explicitly opted into and bounded.

## Scope

This repository contains minimal consumption and security documentation only.
The old generated documentation site and monorepo package structure are not
being migrated.
OAuth for scoped smart-account authority.
