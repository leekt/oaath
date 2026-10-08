# Published Moesi 0.15.3 — 7 October 2026

The runtime now installs exact `moesi@0.15.3` from npm. Its dependency is the
published `cetane@0.0.3`. The registry tarball was checked against npm's SHA-512
integrity; retained archive SHA-256 and download URL are in
[provenance](../vendor/provenance.json). No Moesi checkout is required to rebuild
the product dependencies.

The deployment gate creates manifest v7, as required by this release. It still
requires the exact factory runtime hash at a finalized snapshot and shares the
worker's per-method RPC budget. It only plans and verifies; no Moesi submission
or persisted Run is used by this product. No old-artifact reader or migration
path was added.

Validation:

- Product typecheck, lint, 36 unit tests and all three builds passed.
- `bun scripts/deployment-proof.ts` used the actual product verification function
  against the owned Anvil fixture: correct finalized factory converged, an ERC-20
  at the supplied factory address failed verification, and exhausted admission
  rejected before dispatching another RPC method. No submission occurred.
- The packed dependency/export proof found Moesi 0.15.3 and Cetane 0.0.3, with no
  viem production dependency.
- The restarted runtime authorized a new plan and finalized a real Kernel v4 /
  Uniswap v3 purchase through the packed public SDK.
- Frozen-lockfile install and private Tailscale page/authenticated API checks
  passed after restarting the example and runtime.

The first purchase probe finalized as reverted because the long-running fixture's
feeds were 4,937 seconds old, beyond the approved 3,600-second freshness limit.
Only fixture timestamps were refreshed, retaining their prices. A new plan then
passed; the failed slot was left failed and was not resubmitted.

[Deployment checks](deployment.json) and [dependency graph](package.json) retain
sanitized results. Rust, contract and OAAth source did not change. Their prior
test suites and unrelated crash/cancellation proofs were not rerun. All chain
traffic was confined to owned local fixtures.
