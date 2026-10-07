# Automation product proof — 7 October 2026

The public product has two parts: a Rust API and a TypeScript SDK. The private
OAAth worker is part of the API deployment. DCA is the first supported recipe
and example. Tests use real Kernel v4 / EntryPoint 0.9 and Uniswap v3 on owned
Anvil fixtures, PostgreSQL with independent connections, actual process death,
and exact locally packed packages. Nothing was deployed or published publicly.

## Build and regression evidence

| Check | Result |
| --- | --- |
| Product TypeScript typecheck, Biome lint, three workspace builds | Passed |
| Product codec, HTTP, approval, browser journal and budget tests | 36 passed |
| Rust tests, including five PostgreSQL cases | 8 passed |
| Rust release build, fmt, Clippy with warnings denied | Passed |
| DCA Foundry suite | 20 passed |
| OAAth SDK ordinary suite | 1,294 passed; 31 opt-in cases skipped |
| OAAth server ordinary suite | 210 passed; 29 opt-in cases skipped |
| Scoped signer PostgreSQL suite, independent connections/providers | 4 passed |
| OAAth SDK typecheck, boundary lint and package builds | Passed |

Skipped upstream cases are not claimed as additional network coverage. The
product stack proofs below exercise the selected deployment profile. The
original sibling RPC deduplication change remains separate; its earlier
96-test result is not added to these counts.

## Acceptance proofs

| Command | Proven boundary |
| --- | --- |
| `bun scripts/proof.ts` | Exact packed consumer authorizes and completes a finalized local purchase |
| `bun scripts/negative-proof.ts` | Absent/changed consent rejects; concurrent review keeps identity; missing binding never rotates; terminal plans cannot reactivate |
| `bun scripts/recovery-proof.ts` | Worker dies after bundler acceptance before acknowledgement; two recreated workers recover the same operation with zero replacement sends |
| `bun scripts/boundary-proof.ts` | Process death after reservation, publication and inclusion; missing/prepared evidence stays unresolved; included purchase finalizes without another send |
| `bun scripts/setup-recovery-proof.ts` | Recreated API and worker activate retained consent and complete a purchase without client resubmission, using the same signer |
| `bun scripts/signer-proof.ts` | Independent OS processes converge on one application credential; user/application isolation; exact digest signature; missing custody creates no replacement |
| `bun scripts/shared-key-proof.ts` | Two users share one key but have separate consent/executors/Grants; cross-user access rejects; cancelling one leaves the other's finalized purchase possible |
| `bun scripts/cancel-proof.ts` | Purchase history survives pause/resume and cancellation; executor stop, cleared allowance and Grant revocation are confirmed |
| `bun scripts/wallet-proof.ts` | Packed EIP-1193 owner adapter signs full typed data and executes real Kernel setup; repeated retained approval causes no new send |
| `bun scripts/package-boundary-proof.mjs` | Packed HTTP, React and wallet exports load; OAAth/Moesi production dependency graph contains no viem |
| `bun scripts/ui-proof.mjs` | Tailnet browser session, configuration and page render at 1440px and 390px |
| `bun scripts/ui-lifecycle-proof.mjs` | Exact review, owner approval, pause/resume, cancellation confirmation and reload survive a real local browser flow |
| `bun scripts/ui-review-fixes.mjs` | Rejected inputs unlock; keyboard focus follows review; transition respects reduced motion |
| `bun dev` | Fresh product startup verifies the page and authenticated API through discovered Tailscale forwarding |

Sanitized records: [lost reply](recovery.json), [crash boundaries](boundary.json),
[setup recovery](setup-recovery.json), [signer custody](signer.json),
[shared key isolation](shared-key.json), [package boundary](package.json),
[tailnet access](tailnet.json). Host and origin rejection, authentication and
private-file exclusions were checked through the running preview. Local owner
fixture credentials are absent from the browser and served files.

The wallet proof uses a second owned Anvil fixture and an IndexedDB substitute
for the browser journal. The supplied example uses an explicitly labelled local
test owner. Neither is evidence of a production custody deployment.

## Measured costs

[Raw measurements](local-measurements.json) use the release Rust API on local
Apple Silicon, loopback HTTP and PostgreSQL: 20 warmups, then 1,000 status reads
at concurrency 16. The worker was stopped for this read-path measurement.

| Measurement | Observed |
| --- | --- |
| Status p50 / p95 / p99 | 1.044 / 1.352 / 3.356 ms |
| Short burst throughput | 13,984 requests/second |
| Chain RPC methods for 1,000 reads | 0 |
| HTTP SDK root, minified / gzip | 1,613 / 860 bytes |
| Optional approval entry, gzip | 539 bytes |
| HTTP SDK root runtime imports | 0 |

This short burst does not establish service capacity or live-provider latency.
The package also supplies larger optional React and wallet entries. The small
HTTP root size is not the size of the complete creator. Independent lost-reply
proof status/history reads also incurred zero chain RPC methods.

Integration requires an authenticated backend session endpoint and the supplied
creator/wallet adapter. [llms.txt](../llms.txt) and the
[SDK guide](../sdk/README.md) keep that contract compact. No LLM runs in the
execution path. We have not measured AI integration token savings against a
baseline and make no quantified claim about them.

## Exact sources and limits

[SDK artifact](sdk-artifact.json), [dependency provenance](../vendor/provenance.json)
and [checksums](../vendor/checksums.json) identify the retained bytes. OAAth's
isolated `automation-foundation` branch is `ac05f79`; nine focused patches are
retained in [upstream/](../upstream/README.md). Cetane `9862f7c` and Moesi `0ef5be6`
are clean committed sources. Sibling checkout changes were not imported.

The schema and API are current unreleased definitions, without compatibility
aliases or a data-migration layer. Public-chain configuration, production KMS,
security audit, billing, sponsorship, webhooks and release publication remain
separate work. The UI finish pass resolved rejected-input recovery, keyboard
focus and reduced motion; desktop/mobile screenshots were checked afterward.
