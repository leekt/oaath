# Automation implementation boundary

This repository owns the automation product. The earlier transfer-only OAAth
plan and its assumptions about argument-equality constraints / EntryPoint 0.7
are superseded for this product. Kernel v4 and EntryPoint 0.9 remain pinned.
No migration or compatibility work is required before first release.

The public boundary is Rust API + TypeScript SDK. The private TypeScript worker
uses OAAth's existing authority and Operation machinery. DCA is the first closed
recipe, with its codec and executor owned here. No generic workflow engine is
introduced. Unsupported recipes, routes, chains and tokens fail closed.

Implemented invariants:

- Canonical terms and slot commitments agree in TypeScript, Rust and Solidity.
- Dedicated executor per plan constrains exact account, assets, amount, route,
  price feeds, freshness, total spend, recipient and slot; reverted swaps do not
  consume a successful slot. Owner setup requires a bounded allowance.
- Each reserved slot is bound to the exact core operation before publication.
  Missing evidence and uncertain submission never authorize a second send.
- Durable OAAth signer registry supports `(app,user)` and app scopes. Recovery
  verifies the retained credential; missing custody cannot create another key.
- API sessions bind customer and account. Browser input cannot choose custody
  scope or another account. New application settings do not mutate old plans.
- Consent binds signer, custody mode, scope, fees, request and economic terms.
  Paused/cancelling/terminal plans cannot admit new work. Cancellation confirms
  executor stop, allowance clearing and permission revocation independently.
- Moesi observes finalized deployment state; all worker RPC dispatch shares an
  explicit method budget. Retained status/history requires zero chain reads.
- React creator provides user input, exact review, consent, activity and lifecycle
  actions. DCA example consumes the SDK; owner fixtures are local-only.

Upstream ownership:

- OAAth local branch `automation-foundation` contains keyed headless execution,
  scoped signer persistence and its Cetane runtime adapter. Focused commits and
  exported patches stay separate from the original checkout's RPC dedup work.
- Cetane's published primitives satisfy hashing, ABI, receipt and key
  needs. Moesi's published finalized observer and admission callback satisfy
  observation needs; this product consumes them rather than copying adapters.
- Issues: oaath#385, oaath#386, cetane#7, moesi#89, moesi#90. See upstream/README.md.

The local acceptance boundary includes real Kernel / Uniswap execution,
PostgreSQL independent connections and OS process recreation, packed exports,
lost reply with zero replacement submissions, shared-key cancellation isolation,
and a tailnet browser flow. Evidence is in evidence/automation-product.md.

Still separate scope: public-chain deployment selection, production KMS and
custody operations, external security review, billing, sponsorship, webhooks,
multiple chains/tokens/routes, catch-up, workflow graphs and package publication.
