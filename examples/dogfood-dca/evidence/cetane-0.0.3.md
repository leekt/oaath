# Cetane 0.0.3 update — 7 October 2026

The product, OAAth prerequisites and packed consumer now install Cetane 0.0.3
from npm. The earlier registry E404 has resolved. Registry SHA-512 integrity and
the retained archive SHA-256 are in [provenance](../vendor/provenance.json).
Every file inside the published archive matches the earlier source-built
release commit `5730621c6d6e6edf0fc348f7b58002fc1966349b`; only archive bytes differ.

OAAth protocol and SDK specify 0.0.3. Isolated commit `d81beeb` removes their
temporary source-artifact override; the eleventh [upstream patch](../upstream/README.md)
retains it. The product override also makes Moesi resolve published Cetane 0.0.3.

Registry-switch checks: integrity verification, package-content equivalence,
frozen installs, product typecheck/lint/36 tests/three builds, and the packed
consumer dependency/export proof passed. All reachable Cetane packages resolve
0.0.3; production dependencies remain free of viem. The packer now downloads and
verifies the release instead of rebuilding Cetane from a local checkout.

Checks from the preceding 0.0.3 source update:


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
