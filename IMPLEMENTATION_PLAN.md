# OAAth Automation implementation plan

Status: proposed implementation sequence, 2026-09-29.
Baseline: `f08038afc8c84fdcb10f3ce512b5876cd3afae0d`.
This document plans work; the proposed modules, schemas, and APIs are not implemented.

## 1. Outcome and first milestone

Extend this repository into a product that compiles a constrained automation
definition into an OAAth permission request and an immutable workflow plan,
obtains owner approval, and operates that workflow with durable recovery.

The first milestone is one complete workflow:

> Define a scheduled token transfer → approve its exact authority and plan →
> execute using a service-held session key → restart the worker immediately
> after submission → recover the same operation without another submission →
> pause and revoke the permission.

Initial implementation profile:

- One configured chain, Kernel v4, EntryPoint 0.7, P-256 phone approval, and a
  separate secp256k1 session signer for each deployment.
- One fixed ERC-20 token, recipient, and base-unit amount per deployment;
  zero native value and one transfer call per operation.
- One daily UTC schedule with `missed_run: skip`, plus an authenticated manual
  trigger for development. A missed occurrence is never replayed on restart.
- Onchain restrictions: the exact supported call and argument constraints,
  validity window, and per-chain operation count. Compilation must verify that
  the chosen profile can enforce them.
- At most one unresolved run per deployment, also respecting the core's
  existing grant/chain lane. An unavailable observation keeps the lane occupied.
- PostgreSQL persistence, a service signer provider, bounded project gas
  sponsorship, status APIs, and one outbound event webhook.
- Local Anvil and PostgreSQL prove the milestone. Production deployment writes
  remain deferred under the existing decision for issue #191.

The daily schedule is a runtime condition. It does not promise an onchain daily
token limit. The first milestone excludes arbitrary ABI calls, swaps, incoming
events/webhooks, bridges, general workflow graphs, and native transaction paths.

## 2. One repository, explicit owners

Keep the existing workspace, managed with Bun 1.4.2, and package release group.
Add internal modules to existing packages; a new package is not needed for the
first milestone.

| Location | Responsibility |
| --- | --- |
| `packages/protocol/src/automation/` | Versioned spec, plan, deployment commitment, workflow records, and pure codecs/digests |
| `packages/protocol/src/grant-policy.ts` | Authoritative permission semantics; expand only with a concrete enforcement implementation |
| `packages/protocol/src/operation.ts` | Authoritative chain-operation identity and transitions |
| `packages/sdk/src/client/` and `operation-runner.ts` | Prepare, reserve, authorize, submit, observe, and recover exact operations |
| `packages/server/src/automation/compiler/` | YAML decoding, fixed action compilation, capability checks, enforcement report |
| `packages/server/src/automation/actions/` | Versioned transfer action and its application-level result check |
| `packages/server/src/automation/deployments/` | Immutable deployments, approval binding, activation, pause, replacement, and revocation orchestration |
| `packages/server/src/automation/runtime/` | Trigger occurrences, run/step coordination, leases, and scheduling |
| `packages/server/src/session-signer/` | Durable per-deployment session-key binding and signing integration |
| `packages/server/src/store/` | PostgreSQL implementations of workflow, signer, and required SDK store contracts |
| `packages/server/src/automation/events/` | Durable outbound events, webhook delivery, and operator status projections |
| `packages/contracts/` | Concrete policy contracts when supported guarantees require them |
| `packages/cli/src/automation/` | HTTP clients for compile, deploy, activate, status, pause, and revoke |
| `native/ios/` | Owner review and signatures, including the automation summary and commitment |
| `examples/automation/` | Runnable service/worker composition and a minimal management screen |
| `scripts/` | Packed-consumer and process-recovery proofs |

Expose server automation through an explicit `@oaath/server/automation` entry;
PostgreSQL drivers remain behind the existing Node-only PostgreSQL entry.
Keep package dependencies `server → sdk → protocol`. The CLI can use the HTTP
API without importing the automation runtime. Browser SDK roots must not acquire
YAML parsing, schedulers, PostgreSQL, or server-wallet dependencies.

One repository can run API, worker, and signing processes separately. They share
versioned package contracts, not mutable in-memory authority. Preserve local and
self-hosted SDK usage. All examples and cross-package integrations use public
exports; final integration proof consumes exact local tarballs.

## 3. Existing foundations and concrete gaps

Reuse the existing Grant, permission compiler, owner approval, revocation,
operation runner/observer, PostgreSQL operation store, and phone UI.

The provider path already has `reserve / confirm / abandon` publication hooks
in `packages/sdk/src/client/grant-handle.ts`. The ordinary `OaathSendCallsInput`
does not expose a caller-owned execution key. Reuse that reservation mechanism
for workflow execution through a focused public server-consumer contract; do not
implement a second submission engine or require automation to emulate wallet RPC.

The current KMS signer is a reference provider: its registry is in memory, its
identity is `(clientId, subject, deviceId)`, and it signs a supplied hash. Durable
per-deployment custody and independent payload-policy enforcement are new work.
Persist every grant/context/artifact needed by a headless worker as well as the
key reference; persisting an operation record alone cannot recreate its signer
and authority after a process restart.

Current policy supports target, selector, fixed ABI-word equality, per-call
native value, validity, and per-chain operation counts. ERC-20 aggregate and
periodic budgets need new semantics and concrete onchain enforcement.

## 4. Compilation and approval contract

Use one normalized, versioned spec as the compiler input. YAML is an input
encoding of that spec; API and YAML inputs must compile identically.

Compilation produces:

1. `WorkflowPlan`: schedule, action version, fixed inputs, result check, runtime
   limits, and execution profile.
2. `AuthorizationPlan`: canonical Grant policy, account/chain binding, public
   session credential, owner approval request, and installation requirements.
3. `EnforcementReport`: each restriction's onchain, signer, runtime, or
   unsupported status, with the concrete dependencies and trust assumptions.
4. `DeploymentCommitment`: spec/plan/policy digests, public signer identity,
   account, chain, and pinned compiler/action/runtime profile versions.

Resolve account and asset references before owner review. Bind token address,
decimals, ABI/action version, recipient, and integer base-unit amount. Reject
unsupported token behavior in the initial action profile. Do not use floating
point arithmetic, arbitrary YAML tags, executable expressions, or free-form
network calls. Use bounded established parsers rather than custom languages.

Compilation must be deterministic for the same resolved inputs. Clocks, fetched
metadata, signer creation, and random IDs are explicit inputs or deployment
preparation effects, not hidden inputs to the pure compiler. A finite pinned
Kernel capability table is sufficient initially; do not build a plugin registry.

Required enforcement never downgrades silently. The signer report may claim
independent enforcement only when the provider itself receives and validates
the exact payload and bound policy; a hash-only KMS provider is custody-only.

Owner consent commits to the reviewed plan and Grant through a versioned
deployment commitment. The authorization request, decision binding, phone
projection, and stored deployment must agree. Version changed wire/security
schemas together; reject old schemas rather than adding dual readers.

The core should bind an opaque deployment commitment without interpreting cron
or workflow steps. Onchain permission validation enforces the concrete policy;
it does not automatically enforce the entire workflow digest or schedule.
Runtime and any enforcing signer verify the approved deployment commitment.

Changing execution behavior, signer, authority, or chains creates a new
deployment and requires owner approval. Names and webhook destinations are
separate operational metadata with change history. Never mutate the meaning of
an already approved deployment.

## 5. Durable execution and state ownership

| Record | Authoritative owner and required evidence |
| --- | --- |
| Automation | Logical identity, workspace membership, and selected deployment |
| Deployment | Immutable plan/approval commitment plus lifecycle revision |
| Session binding | Deployment, public credential, sealed/provider key reference, and core Grant reference |
| Trigger occurrence | Deployment, canonical scheduled UTC instant or authenticated manual idempotency key |
| Run / Step | Workflow progress, fixed resolved inputs, action result, and core execution reference |
| Execution intent | Stable caller key, input digest, reservation revision, and exact operation pointer |
| Operation / attempt evidence | Existing OAAth core identity, submission evidence, inclusion, finality, and recovery state |
| Gas reservation | Project/deployment budget owner, reserved maximum cost, and settled actual cost |
| Event outbox | Stable event ID, public payload, delivery state, and bounded retry schedule |

Use a durable uniqueness key scoped to workspace, deployment, trigger occurrence,
and step. Repeating the same key and inputs returns the existing execution;
different inputs under that key are a conflict. Do not make an `attempt_id` a
second writable source of submission truth: expose core attempt evidence by
reference when required.

### Submission handoff

1. Persist the occurrence and run/step execution intent before any effect.
2. Prepare through the core and reserve its exact identity against the intent
   before signing or submission. A different reserved identity is a conflict.
3. Persist the core prepared record and finish the existing publication handshake.
4. Authorize and submit through the core's existing durable submission protocol.
5. On restart, resolve the caller key to its retained pointer and reconcile it
   with the core store before taking another action.

There must be a recoverable record for every crash boundary, including intent
without reservation, reservation before core publication, and submitted operation
before worker acknowledgement. Use transactional/CAS reservations and the existing
publication protocol; do not assume two unrelated writes commit atomically.
An unreadable record, missing receipt, expired worker lease, or lost response
never permits a new identity or submission. A provably unsent prepared identity
may resume only through the core's existing recovery rules.

Workflow progress is `queued → running → succeeded | failed | cancelled`, with
`blocked` and `reconciling` for work awaiting resolution. A run succeeds only
after core finality and its action's result check. Submitted/included/finalized
labels displayed by the product are projections of core evidence. Reorg handling
belongs to the core; the workflow waits for its resulting evidence.

### Resource and lifecycle rules

- An unresolved intent occupies its workflow slot; the core owns the operation
  lane. Lease expiry only changes which worker may reconcile it.
- Persist claim generations and reject stale workers at effect admission.
  Independent workers must contend through PostgreSQL, not process-local locks.
- Reserve maximum project gas cost before admission; retain reservations while
  outcomes are unknown. Settle from verified receipts and include reverted
  attempts. Reject unsupported payer cost bounds rather than promising a cap.
- Activation verifies owner consent, signer recovery, the approved commitment,
  and the exact chain/runtime profile. The initial profile can use the core's
  atomic install-and-execute path: label it ready for first execution, not already
  installed. Installation evidence remains a separate chain-local fact.
- Pause closes admission for new runs/signing and stops queued work. It must
  account for in-flight signing admissions before reporting quiescence. Existing
  signed/submitted work remains observable and may still execute.
- Revoke closes admission and invokes core revocation, retaining per-chain
  progress and install-approval invalidation. Deleting keys or records does not
  complete revocation. Resume after pause requires valid, unrevoked authority.
- A replacement deployment does not silently take over unresolved work or budget
  reservations. Stop old admission, reconcile old work, and explicitly authorize
  the replacement and any permitted overlap.
- Cleanup attempts all required resource releases. Preserve the primary failure;
  retain unresolved effects and custody needed for reconciliation. Sign-out,
  local deletion, resource closure, pause, and revoke remain separate actions.

## 6. Implementation sequence

Each numbered stage has one delivery gate. Split protocol, server, contract, and
UI changes into focused PRs inside a stage; merge tested prerequisites first.
Follow AGENTS.md scope and evidence rules without adding a review phase.

| Stage | Deliverable and owner | Smallest proof / blocking regression | Depends on |
| --- | --- | --- | --- |
| 1 | Protocol records and commitments: normalized spec, workflow/deployment records, execution-key binding, explicit versions | Deterministic digests; changed action/input/chain/signer changes commitment; unsupported or malformed schema rejected | Baseline |
| 2 | SDK durable workflow handoff using existing publication hooks; PostgreSQL execution-intent store | Two workers using one key produce one operation; changed input conflicts; crash after send but before acknowledgement recovers without a send | 1 |
| 3 | Durable per-deployment signer and headless Grant/context recovery in the server | New processes recover the same public key and authority; unavailable custody creates neither a replacement key nor a signature; another deployment cannot use that signer | 1 |
| 4 | Transfer action, YAML compiler, pinned capability profile, enforcement report | YAML/API equivalence; exact calldata and policy; wrong recipient/amount/selector and unsupported required constraints rejected; accepted contract path proved on Anvil | 1 |
| 5 | Deployment approval and activation across protocol, server, and phone | Reviewed commitment equals activated deployment; changed plan/signer requires fresh consent; unreadable or mismatched readiness blocks activation | 3, 4 |
| 6 | Scheduler, worker, manual admission, gas reservations, pause, and revoke orchestration | Duplicate ticks and two independent workers run once; missed slots skip; uncertain submission blocks new work; pause/signing and revoke/execution races retain truthful state | 2, 5 |
| 7 | Management API, CLI, minimal example screen, and outbound event outbox | Owner can inspect authority, next run, operation evidence, failure, cost, pause, and revoke; repeated webhook delivery keeps one event ID; delivery failure never repeats execution | 6 |
| 8 | Complete packed, multi-process local workflow and operator instructions | One consent, scheduled transfer, forced worker/service restarts, same-operation recovery, and finalized revocation; no new send during recovery | 7 |

Stage 2 is the first behavioral implementation. Build its forbidden-transition
regressions before broad compiler or scheduling work. Stages 3 and 4 can follow
independently once stage 1 is merged; they do not justify a generic runtime layer.

Stage 5 includes a small browser management/consent entry and a separate native
presentation change. Both show the action, schedule, recipient, amount, expiry,
counts, signer custody, and actual enforcement levels. Existing consent and
match-code behavior remain the foundation. New UI follows repository frontend
defaults; existing phone UI retains its established design.

### Proposed first API surface

These routes are implementation targets, not existing endpoints. Apply the
existing workspace/client authorization to each resource and admission.

| Route | Purpose |
| --- | --- |
| `POST /automations/compile` | Normalize the spec and return plan, required authority, and enforcement report |
| `POST /automations/deployments` | Create an immutable candidate and public signer binding |
| `POST /automations/deployments/{id}/authorize` | Start/link existing owner consent; never accept a caller's claim of approval |
| `POST /automations/deployments/{id}/activate` | Verify consent/readiness and open admission |
| `POST /automations/deployments/{id}/runs` | Admit a manual occurrence with a required idempotency key |
| `GET /automations/deployments/{id}` | Authority, lifecycle, installation evidence, and next occurrence |
| `GET /automations/runs/{id}` | Workflow result plus referenced core operation evidence and costs |
| `POST /automations/deployments/{id}/pause` | Close admission and report outstanding work |
| `POST /automations/deployments/{id}/resume` | Recheck valid authority and reopen admission without catch-up runs |
| `POST /automations/deployments/{id}/revoke` | Start/link core revocation and any required owner signature |

CLI commands live under `oaath automation …`, separate from runtime-contract
deployment commands. Existing HTTP authorization/decision routes continue to own
the owner decision. API keys and scheduler credentials cannot enlarge a Grant.

## 7. Evidence and milestone acceptance

Use focused tests for each stage. Run relevant PostgreSQL, Anvil, browser, or
Swift evidence only where that stage crosses the corresponding boundary. Keep
fixtures/local transports as defaults and paid/shared RPC access explicitly
opted in and bounded.

The final milestone gate must prove:

- One approved immutable deployment produces a scheduled fixed transfer through
  packed packages, the canonical permission path, and real local contracts.
- Two worker processes and independent PostgreSQL connections cannot create two
  executions for one occurrence or exceed the reserved gas budget.
- Kill/recreate processes at every handoff boundary, especially after broadcast
  and before acknowledgement. Retain account, signer, nonce, operation identity,
  and reservations. Recovery submits zero additional operations.
- Receipt absence, provider failure, unreadable state, and a pre-finality reorg
  remain unresolved until the core obtains sufficient evidence.
- An action succeeds only when its supported token transfer result and core
  finality agree. A successful receipt alone is not the application result.
- Wrong recipient/amount/target/selector, expiry, exhausted operation count, and
  modified plan or signer cannot execute under the approved deployment.
- Pause prevents newly admitted execution; already signed/submitted work remains
  visible. Finalized revocation prevents new execution and consumed approvals
  cannot reinstall authority through the supported path.
- A fresh service and worker recover from production store adapters. Memory
  stores, copied live handles, direct database injection, or reusing a process do
  not prove restart behavior.
- Packed imports, public-surface checks, package types/builds, and the final
  repository gate pass. No package is published or production chain modified by
  this milestone. The existing fixed `0.x.y` group remains intact.

## 8. Follow-on increments

These remain within this repository and start only after the first workflow is
proven. They are separate deliverables, not prerequisites for the initial gate.

| Increment | Scope and completion gate |
| --- | --- |
| Trigger expansion | Cron/IANA timezones with explicit DST behavior, then authenticated incoming webhooks and finalized chain-event cursors. Persist occurrences and prove duplicate delivery/reorg handling. Add price/state triggers only with a defined data freshness profile. |
| Token budgets | Add per-execution, aggregate, and fixed-window token limits to shared policy plus concrete contracts. Prove atomic enforcement across concurrent runs and sessions, deliberate budget identity across deployment replacement, and no unintended reset on reauthorization. Runtime reservations remain separate from onchain counters. |
| Swap action | Pin token/router/spender/ABI versions; bind approval amount, recipient, deadline, and min output. Track quote provenance and age. Independent price guarantees require an explicit oracle/guard profile. Prove action success and required atomicity on the actual contract path. |
| Stronger signing integration | Add a provider boundary that independently validates the exact approved operation payload and policy before signing. Keep custody-only providers accurately labeled. Prove caller input cannot substitute another operation or bypass the provider's validation. |
| Native execution profiles | Pin EIP-8130/EIP-8141 specification and client/contract revisions in separate devnets. Extend account authorization, operation identity, signing, result evidence, and revocation together. Derive shared interfaces from tested implementations, without assuming a transport-only change. Unsupported combinations remain inactive. |
| Explicit cross-chain routes | Add ordered steps with source finality, destination evidence, chain-local budget allocation, and approved recovery actions. A partially completed route retains intermediate assets and unresolved operations; no generic cross-chain DAG or atomic global budget claim. |
| Managed operation | Expand status UI, delivery controls, usage accounting, retention, and then billing. Validate first-customer value and operating cost before pricing commitments. Deployment admission must still enforce project limits independently of billing. |

### Deferred API consolidation decisions

Public functions should not depend on Kernel version, EntryPoint version, key
kind, or transport. Where entry points do the same job and differ only in
implementation, they become one entry point with optional settings. Two pairs
were deliberately kept separate during the 2026-09-29 DevEx review. Revisit
both when the consolidation stack lands, and again at the release-candidate
boundary:

| Kept separate | Why | Revisit when |
| --- | --- | --- |
| `ownerOperator` vs `sessionOperator` (`packages/sdk/src/kernel/operator/`) | They change who holds authority (root validation vs a scoped permission), so the difference is semantic, not an implementation detail. AGENTS.md treats operator role as its own composition axis. | A consumer needs to choose authority at runtime from data, or a third authority kind appears. Then consider `operator({ authority?: "session" })` with the same two owners behind it. |
| EIP-5792 vs ERC-7836 handling in `oaathProvider` (`packages/sdk/src/provider/`) | These are the wallet RPC standards callers speak, and both already sit behind one provider entry. | Either standard is superseded, or adopters need to enable only one. Then consider an optional `standards` setting on `oaathProvider`. |

The native specifications are evolving inputs, not a launch promise. References:
[EIP-8130](https://eips.ethereum.org/EIPS/eip-8130) and
[EIP-8141](https://eips.ethereum.org/EIPS/eip-8141).

Before a release-candidate decision, choose the actual pilot workflow, chain,
account version, token/action profile, custody provider, and payer. Production
rollout approval, production credentials, comprehensive security review, SLA,
pricing, and release publication remain separate decisions. Measure time from
approval to first execution, recurring use, recovery duration, duplicate
executions, customer operational burden, and cost per completed run.
