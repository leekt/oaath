# Cetane 0.0.3 update — 7 October 2026

The product and its packed consumer now resolve Cetane 0.0.3 from clean release
commit `5730621c6d6e6edf0fc348f7b58002fc1966349b`. At verification, npm returned
E404 for `cetane@0.0.3`; this is an exact source-built release tarball, not a
registry artifact. Its SHA-256 is recorded in
[dependency provenance](../vendor/provenance.json).

OAAth protocol and SDK dependency declarations now specify 0.0.3, in isolated
commit `eb4536e` and the tenth [upstream patch](../upstream/README.md). Moesi's
transitive dependency also resolves the same exact artifact through the product
override. The canonical-module inventory is additive; existing Cetane source
files used by this product did not change from the prior pinned commit.

Checks rerun for this update:

- OAAth protocol: 258 tests passed.
- OAAth Cetane adapter, read-only ports, wallet ECDSA and headless execution:
  38 tests passed; SDK typecheck and boundary lint passed.
- Product typecheck, lint, 36 tests and all three workspace builds passed.
- Exact packed public HTTP, React and wallet exports loaded. The dependency
  walk checks every reachable Cetane version in both runtime and packed SDK
  consumer graphs; all were 0.0.3. No viem production dependency was found.
- Packed EIP-1193 owner adapter signed complete typed data and performed real
  Kernel v4 setup on an isolated Anvil fixture; repeating approval sent nothing.
- Recreated product worker completed a finalized Kernel v4 / Uniswap v3 purchase
  through the packed SDK on the existing owned local fixture.
- Frozen-lockfile install passed. The restarted preview and authenticated API
  remained accessible through the existing private Tailscale endpoint.

Rust and contract code did not change. Their prior evidence, crash-boundary
proofs and shared-key isolation proofs were not rerun for this dependency-only
update. No public-chain traffic, package publication or live-provider
performance measurement was performed.
