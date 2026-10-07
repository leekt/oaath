# Managed DCA implementation

Prepared for OAAth product and engineering on 7 October 2026.

The product has two public surfaces: a Rust HTTP API and a TypeScript SDK.
The service includes a private TypeScript execution worker to retain OAAth's
Grant, signing, operation identity, submission and finality owners. Rust owns
application authentication, plans, scheduling, runs and projections. Cetane
supplies ABI and chain reads through explicit imports; Moesi verifies executor
deployments. Neither submits scheduled purchases outside OAAth.

## Delivery invariants

1. Versioned canonical terms and slot commitment. Changed economic terms
   invalidate consent; unsupported versions fail closed.
2. Dedicated executor per plan; fixed standard tokens, route, exact input,
   account recipient, bounded allowance, independently checked fresh prices,
   daily schedule and atomic successful-slot consumption.
3. Durable keyed intent before submission, immutable digest and exact OAAth
   operation pointer. An uncertain outcome never permits another send.
4. PostgreSQL signer, Grant and consent recovery. Missing custody never creates
   a replacement key. Activation requires matching setup and consent evidence.
5. Indexed due work, fenced claims, skipped missed slots, failed finalized
   reverts, bounded observation, pause and confirmed cancellation.
6. Public API and packed TypeScript consumer over real local Kernel v4,
   EntryPoint 0.9, swap contracts, PostgreSQL and process recreation.

Each stage is a focused change with at most 25 non-generated files and 2,000
added non-generated lines. Tests cover the accepted path and forbidden
transitions before broad implementation. Upstream prerequisites live in the
isolated `.local/oaath-dca` worktree at baseline
`895bc93b6408537d736100ac20d577711313717c`; exact tarballs cross repository
boundaries. Existing sibling RPC and observation changes remain separate.

## Local deployment choices

The proof uses owned Anvil and PostgreSQL, one local chain, standard fixture
USDC (6 decimals) and WETH (18 decimals), a pinned Uniswap v3 exact-input route,
and two 8-decimal price feeds. Local feeds are test fixtures, not live market
price evidence. The executor validates freshness and derives minimum output.
All feed addresses, freshness, fees and slippage are reviewed before consent.
Public-chain choices remain separate deployment work.

Slots are zero based. Slot `s` opens at `startAt + s * 86400`, and closes
exclusively 900 seconds later. The fixed end is the final slot's exclusive
close. Late authorization never moves the reviewed start. Skips and finalized
failures do not create replacement opportunities. The account pays gas;
service fees are zero in this proof and gas ceilings are separately reviewed.

## State and recovery

Rust owns draft, awaiting_consent, authorized, active, paused, cancelling,
cancelled, completed and expired plan states with compare-and-swap revisions.
Only active plans admit slots. Terminal states never reactivate. Unresolved
operations survive plan expiry and continue observation.

The run store owns `(planId, slot)`, immutable inputs, claim generation and the
OAAth intent reference. OAAth alone owns lane occupancy, submission attempts,
inclusion and finality. Lease expiry changes the reconciler, not authority to
send. Missing receipts or operation records remain unresolved. Projection
updates may retry without changing execution identity.

Cancellation closes admission immediately. It completes only after executor
stop and required Grant revocation are confirmed. Pending owner action and
already submitted work remain visible. Key deletion is separate cleanup.

## Reconciliation with the older OAAth plan

The transfer-oriented upstream plan is superseded for this DCA milestone:
swaps replace transfers, executor enforcement replaces unsupported argument
equality, and the runtime is Kernel v4 with EntryPoint 0.9. Preserve its durable
intent and crash-boundary requirements. OAAth's dependency direction remains
`server -> sdk -> protocol`; the Rust service integrates through a narrow
private bridge, without porting or duplicating the operation state machine.

Moesi `0.15.2` currently pins OAAth `0.3.0`; the baseline OAAth packages are
`0.3.4`. Deployment verification can use Moesi core's public observer seam.
Using its OAAth adapter requires a separately proved compatibility update.

## Optimization evidence

Avoid polling idle plans or polling from status viewers. Use PostgreSQL due
indexes, short claims, shared bounded RPC clients, bounded observation backoff,
and retained projections. Preserve fresh canonicality checks. Count dispatched
RPC methods, retries and submissions separately from HTTP envelopes. Benchmark
local API latency, database contention, RPC counts, worker throughput, browser
bundle size and recovery with exact dependency provenance. No live-network
performance or production-readiness claim follows from local measurements.

The prior RPC deduplication evidence (96 focused tests, typecheck, lint and a
packed local HTTP proof) belongs to the separate upstream change.

## Deferred work

Multiple chains, arbitrary tokens/routes, catch-up buys, sponsorship, billing,
webhooks, polished management UI, generic workflows, production deployment,
package publication and release-candidate security work remain out of scope.
