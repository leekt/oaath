# Local proof — 7 October 2026

This evidence covers the local implementation, using real Kernel v4 / EntryPoint
0.9 and Uniswap v3 on owned Anvil, PostgreSQL with independent connections,
recreated API/execution processes, and exact local package tarballs. It does not
measure a public chain or live provider.

## Checks

| Check | Result |
| --- | --- |
| Rust tests, including owned PostgreSQL | 7 passed |
| Public SDK, approval journal and RPC budget tests | 6 passed |
| OAAth protocol suite | 284 passed |
| OAAth SDK suite | 1,294 passed; 31 opt-in cases skipped |
| OAAth server suite, PostgreSQL enabled | 235 passed |
| Solidity suites | 30 passed, including 20 DCA regressions |
| Rust release build, fmt, Clippy with warnings denied | Passed |
| Product TypeScript check, lint and both package builds | Passed |
| OAAth workspace typecheck, lint, public-surface gate | Passed |

The actual local stack proof covers the selected Kernel profile; the skipped
upstream cases are other opt-in fixture/matrix tests, not evidence of additional
network coverage. The SDK's six keyed-execution tests cover exact identity
recovery, conflicting digests, absent evidence, publication boundaries and
concurrent calls. Rust and live API tests exercise actual guarded transitions,
not a second transition model.

The [lost-reply proof](recovery.json) kills the worker after the bundler accepts
the operation and before returning its acknowledgement. Two recreated workers
recover the same identity and signer with **zero replacement submissions**.
The [boundary proof](boundary.json) uses real process death after reservation,
after core publication, and after inclusion with finality held back. Missing or
prepared records remain unresolved; the included operation finalizes without
another send. [Setup recovery](setup-recovery.json) recreates both the Rust API
and execution service, then activates retained consent and completes a purchase
without another approval submission.

The final packed consumer completed a purchase, paused/resumed, and cancelled
with confirmed executor stop, allowance removal and Grant revocation. It
rejected absent/changed consent, missing custody, and cancelled-plan resume.
Concurrent reviews returned the same signer and commitment. The supplied owner
flow retained its setup attempt after a lost reply instead of repeating it.

## Measured optimization

[Raw measurements](local-measurements.json): release Rust build on this Apple
Silicon machine, local PostgreSQL and loopback HTTP, 20 warmups followed by 1,000
status requests at concurrency 16. Workers were stopped to isolate the read path.

| Measurement | Observed |
| --- | --- |
| Status latency p50 / p95 / p99 | 0.833 / 1.287 / 3.177 ms |
| Burst throughput | 17,204 requests/second |
| Chain RPC methods for 1,000 status reads | 0 |
| SDK root, minified / gzip | 1,672 / 886 bytes |
| Optional approval entry, gzip | 536 bytes |
| SDK root runtime dependencies | 0 |

This is one short local burst, not a capacity, durability-under-load, or
live-network performance claim. Tailscale health and authenticated API access
were verified separately, along with authentication, exact-origin preflight,
rejected origins and private-file exclusion. HTTP envelopes are not counted as
RPC savings.

## Provenance

[Dependency provenance](../vendor/provenance.json), [artifact checksums](../vendor/checksums.json)
and [the public SDK artifact](sdk-artifact.json) identify retained bytes.
OAAth changes are the three isolated [prerequisite patches](../upstream/README.md).
Moesi uses its public core observer seam at the retained baseline. Cetane is an
exact packed working-tree snapshot; its tarball checksum is authoritative and
its uncommitted source changes are not attributed to this DCA change.

The sibling OAAth RPC deduplication work and Moesi observation work remain
untouched. The existing separate 96-test RPC-deduplication evidence is not added
to these counts or presented as a live-network measurement.
