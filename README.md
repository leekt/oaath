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

The current package intentionally exports no product API. Public capabilities
are added only when their invariant owner and focused proof land together.

## Development

Requirements:

- Node.js 22.13 or newer
- pnpm 11.15.1

```sh
pnpm install
pnpm check
```

Automated tests must not contact paid or shared RPC services. Contract and
runtime integration tests use local Anvil unless a dedicated live-network suite
is explicitly opted into and bounded.

## Scope

This repository contains minimal consumption and security documentation only.
The old generated documentation site and monorepo package structure are not
being migrated.
OAuth for scoped smart-account authority.
