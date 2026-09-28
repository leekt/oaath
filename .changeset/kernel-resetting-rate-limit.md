---
"@oaath/sdk": minor
---

Add a `rate-limit` Kernel policy profile for an explicit number of validated
operations per fixed interval. It composes with call/value bounds, expiry and
the independent lifetime operation count. The public compiler captures positive
canonical interval/count values and emits deterministic policy order. Existing
policy identities stay unchanged when this profile is absent.

The pinned contract owns the remaining quota and reset time per account and
permission. Installation starts the first window. The first validation at or
after its end replenishes the quota and starts a new interval; unused quota
does not accumulate. A validated operation consumes a slot even when execution
reverts. A reverted validation transaction rolls back its quota change. Runtime
recreation reads chain state and does not reset the quota or permit submission
retries. Existing operation journals and their unresolved-lane rules are unchanged.

This profile uses a distinct deterministic module deployment; every bind proves
its exact runtime hash on the action chain. Missing or different code fails with
`kernel_runtime_policy_unavailable`. No deployment is implied or performed by
adding the profile. The source, compiler input, licenses and deployment bytes
are checked in and reproducible with `pnpm --filter @oaath/sdk check:rate-limit-artifact`.

This is the public Kernel composition primitive needed for Orchestra's daily
cap. Default Grant policy and permission-request schemas are unchanged; their
application integration remains separate.
