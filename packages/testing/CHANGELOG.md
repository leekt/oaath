# @oaath/testing

## 0.2.0

### Minor Changes

- 399ae1a: Add durable direct-Grant local Anvil fixtures and a read-only recovery client
  that reopens SDK state after OS process loss without credentials or resubmission.
  Receipt discovery now reads actual EntryPoint logs instead of process-local
  transaction lookup. Expose SQLite adapters for SDK composition and bump the
  disposable test database schema to v2; old files must be recreated.

### Patch Changes

- 25335ee: Expose a Node-only `@oaath/testing/anvil` fixture that owns real local Kernel/EntryPoint chains, test authorization, reopenable client storage, and cleanup. External consumers can prove all-chain execution and operation recovery from public packed packages without copying OAAth transports or credentials. Requires the local Anvil executable; never a production dependency.
- Updated dependencies [f185d49]
- Updated dependencies [5205bc7]
- Updated dependencies [ae7b016]
- Updated dependencies [bcf1498]
- Updated dependencies [8720b76]
- Updated dependencies [8ee17d3]
- Updated dependencies [8240e65]
- Updated dependencies [8e69b53]
- Updated dependencies [138440f]
- Updated dependencies [1d3e985]
- Updated dependencies [5fa5e2f]
- Updated dependencies [b090f68]
- Updated dependencies [439f120]
- Updated dependencies [b8b1c94]
- Updated dependencies [f3ea421]
- Updated dependencies [98aebeb]
- Updated dependencies [353a37d]
- Updated dependencies [7a3c96a]
  - @oaath/server@0.2.0
  - @oaath/sdk@0.2.0
  - @oaath/protocol@0.2.0

## 0.1.0

### Minor Changes

- Publish the first public OAAth proof-of-concept release: runtime-neutral protocol
  contracts, the Kernel v4 browser SDK, the relay/PostgreSQL server, and
  deterministic test support.

### Patch Changes

- Updated dependencies
  - @oaath/protocol@0.1.0
  - @oaath/sdk@0.1.0
