# OAAth Automation implementation plan

Status: proposed implementation sequence, revised 2026-09-29.
Baseline: `ebd1d28feecd37c827749e7176d29b1bd41d2410` (after the Bun 1.4.2 migration).
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

Anything not needed to prove that sentence is deferred (§8).

Initial implementation profile:

- One configured chain, Kernel v4, EntryPoint 0.7, P-256 phone approval, and a
  separate secp256k1 session signer for each deployment.
- One pinned, known-standard ERC-20 token, one recipient, and one base-unit
  amount per deployment; zero native value and one transfer call per operation.
  Token support is decided by pinning, not by detecting token behavior.
- One daily UTC schedule with `missed_run: skip` and a fixed admission grace
  window (§5), plus an authenticated manual trigger for development. A missed
  occurrence is never replayed on restart.
- Onchain restrictions use the existing `GrantPolicy` only: exact target,
  `transfer` selector, `argumentEquals` on ABI words 0 (recipient) and 1
  (amount), `valueLimit` 0, validity window, and `perChainOperationLimit`. No
  new contracts are required for the milestone.
- The account pays its own gas. No paymaster or project gas sponsorship.
- PostgreSQL persistence, a local sealed session-signer provider, and a status
  API.
- Local Anvil and PostgreSQL prove the milestone. Production deployment writes
  remain deferred under the existing decision for issue #191.

The daily schedule is a runtime condition. It does not promise an onchain daily
token limit. `perChainOperationLimit` bounds the total number of operations for
the deployment's lifetime, and a reverted operation consumes one use. The first
milestone excludes YAML input, gas sponsorship, webhooks, a CLI, a management
screen, arbitrary ABI calls, swaps, incoming events, bridges, general workflow
graphs, and native transaction paths.

## 2. One repository, explicit owners

Keep the existing workspace, managed with Bun 1.4.2, and package release group.
Add internal modules to existing packages; a new package is not needed for the
first milestone.

| Location | Responsibility |
| --- | --- |
| `packages/protocol/src/automation/` | Versioned spec, execution-key binding, deployment commitment, and pure codecs/digests, each added by the stage that first consumes it |
| `packages/protocol/src/grant-policy.ts` | Authoritative permission semantics; unchanged for the milestone |
| `packages/protocol/src/operation.ts` | Authoritative chain-operation identity and transitions |
| `packages/sdk/src/client/` and `operation-runner.ts` | Prepare, reserve, authorize, submit, observe, and recover exact operations, including the caller-keyed execution entry (§3) |
| `packages/server/src/automation/compiler/` | JSON spec decoding, fixed transfer compilation, pinned capability check, enforcement report |
| `packages/server/src/automation/actions/` | Versioned transfer action and its result check |
| `packages/server/src/automation/deployments/` | Deployment lifecycle state machine: approval binding, activation, pause, resume, and revocation orchestration |
| `packages/server/src/automation/runtime/` | Trigger occurrences, run coordination, claims, and scheduling |
| `packages/server/src/session-signer/` | Durable per-deployment session-key binding, sealing, and signing |
| `packages/server/src/store/` | PostgreSQL implementations of deployment, run, intent, signer, and required SDK store contracts |
| `examples/automation/` | Runnable API/worker composition used by the final proof |
| `scripts/` | Packed-consumer and process-recovery proofs |

Expose server automation through an explicit `@oaath/server/automation` entry;
PostgreSQL drivers remain behind the existing Node-only PostgreSQL entry. Keep
package dependencies `server → sdk → protocol`. Browser SDK roots must not
acquire schedulers, PostgreSQL, or server-wallet dependencies.

API and worker processes run separately. They share versioned package contracts
and PostgreSQL state, not mutable in-memory authority. Preserve local and
self-hosted SDK usage. Examples and cross-package integrations use public
exports; the final integration proof consumes exact local tarballs.

## 3. Existing foundations and concrete gaps

Reuse the existing Grant, permission compiler, owner approval, revocation,
operation runner/observer, PostgreSQL operation store, and phone UI.

The provider path already has `reserve / confirm / abandon` publication hooks
in `packages/sdk/src/client/grant-handle.ts`. The ordinary `OaathSendCallsInput`
does not expose a caller-owned execution key. Stage 2 adds one public SDK entry
for server consumers, with this minimum shape (names final in Stage 2):

```text
executeKeyed({ executionKey, inputDigest, calls, publication: { reserve, confirm, abandon } })
  -> { status: "submitted" | "recovered", operation: OperationPointer }
   | { status: "conflict" }            // same key, different inputDigest or identity
   | { status: "unresolved", operation: OperationPointer }
```

It reuses the existing reservation mechanism; it is not a second submission
engine and does not emulate wallet RPC.

The current KMS signer is a reference provider: its registry is in memory, its
identity is `(clientId, subject, deviceId)`, and it signs a supplied hash.
Durable per-deployment custody is new work. Persist every grant/context/artifact
needed by a headless worker as well as the key reference; an operation record
alone cannot recreate its signer and authority after a restart.

## 4. Compilation and approval contract

The compiler input is one normalized, versioned JSON spec submitted through the
API. YAML is deferred (§8).

Compilation produces:

1. `WorkflowPlan`: schedule, grace window, action version, fixed inputs, result
   check, and execution profile.
2. `AuthorizationPlan`: canonical Grant policy, account/chain binding, public
   session credential, owner approval request, and installation requirements.
3. `EnforcementReport`: each restriction's `onchain` or `runtime` status. The
   milestone signer is custody-only and is reported as such; it never claims
   independent enforcement.
4. `DeploymentCommitment`: spec/plan/policy digests, public signer identity,
   account, chain, and pinned compiler/action/runtime profile versions.

Resolve account and token references before owner review. Bind token address,
decimals, action version, recipient, and integer base-unit amount. Only the
pinned token is accepted. Do not use floating point arithmetic, executable
expressions, or free-form network calls.

Compilation is deterministic for the same resolved inputs. Clocks, fetched
metadata, signer creation, and random IDs are explicit inputs or deployment
preparation effects. A finite pinned Kernel capability table is sufficient; do
not build a plugin registry. Required enforcement never downgrades silently.

Owner consent commits to the reviewed plan and Grant through a versioned
deployment commitment. The authorization request, decision binding, phone
projection, and stored deployment must agree. Version changed wire/security
schemas together; reject old schemas rather than adding dual readers.

The core binds an opaque deployment commitment without interpreting the
schedule. Onchain validation enforces the concrete policy only; the runtime
verifies the approved commitment before every signing admission.

Changing execution behavior, signer, authority, or chain requires a new
deployment and fresh owner approval. Never mutate an approved deployment.

## 5. Durable execution and state ownership

| Record | Authoritative owner and required evidence |
| --- | --- |
| Deployment | Immutable plan/approval commitment, lifecycle state, and revision |
| Session binding | Deployment, public credential, sealed key reference, and core Grant reference |
| Trigger occurrence | Deployment, canonical scheduled UTC instant or authenticated manual idempotency key |
| Run | Occurrence, fixed resolved inputs, workflow status, action result, and execution-intent reference |
| Execution intent | Stable execution key, input digest, state, claim generation, and exact core operation pointer |
| Operation / attempt evidence | Existing OAAth core identity, submission evidence, inclusion, finality, and recovery state |

Run occupancy has one owner: the core's `(grantId, chainId)` lane. Each
deployment has exactly one Grant and one chain, so "one unresolved run per
deployment" is derived from the core lane and the execution intent, not stored
as a separate slot.

The execution key is `(deploymentId, occurrenceId)`. Repeating the same key and
input digest returns the existing execution; a different digest is a conflict.
Core attempt evidence is exposed by reference, never copied as a second
writable truth.

### Deployment lifecycle

```text
state and owner      deployments/ state machine, persisted row with revision (CAS)
states               candidate → awaiting_consent → authorized → active ⇄ paused
                     active|paused → revoking → revoked
                     candidate|awaiting_consent → abandoned
terminal             revoked, abandoned
persisted evidence   commitment digest, consent decision reference, activation
                     readiness check, revocation operation pointer
resource occupied?   active: admission open; paused: admission closed, in-flight
                     intents still reconciled; revoking/revoked: admission closed
crash or reload      state is read from PostgreSQL; revoking resumes by observing
                     the retained revocation operation, never by resubmitting
cleanup owner        revocation orchestration; key deletion is a separate
                     explicit effect after revoked, never part of revocation
```

Forbidden transitions (tested before broad implementation):

- `awaiting_consent → active` without a verified consent decision bound to the
  same commitment digest.
- `paused → active` after `revoking` has started, or when authority is expired
  or exhausted.
- `revoking → active|paused`; `revoked → *`.
- Any transition that changes the commitment of an existing deployment.

### Execution intent

```text
state and owner      runtime/ intent row keyed by (deploymentId, occurrenceId)
states               admitted → reserved → published → submitted → finalized
                     admitted|reserved → abandoned   (only if provably unsent)
                     submitted → unresolved → submitted (observation retry only)
terminal             finalized, abandoned
persisted evidence   input digest, reserved core identity, publication pointer,
                     core submission evidence
resource occupied?   every non-terminal state occupies the deployment's lane
retry positively     only observation; a new identity or submission is never
safe?                allowed after reserved
crash or reload      resolve the key to its pointer and reconcile with the core
                     store before any action
cleanup owner        the claiming worker; lease expiry only changes which worker
                     may reconcile
```

Forbidden transitions:

- Any state after `reserved` → a different core identity.
- `unresolved → abandoned` or a new submission on receipt absence, provider
  failure, unreadable state, expired lease, or lost response.
- A stale claim generation admitting any effect.

Crash boundaries that must each have a recoverable record and a restart test:

1. intent admitted, not reserved;
2. reserved, not published to the core;
3. published, not submitted;
4. submitted, before worker acknowledgement;
5. included, before finality and result check.

Use transactional/CAS writes and the existing publication protocol; do not
assume two unrelated writes commit atomically.

### Runs and scheduling

Run status is `queued → running → succeeded | failed | cancelled`, with
`reconciling` while the core has not produced sufficient evidence.

- An occurrence at scheduled instant `T` may be admitted only while
  `T ≤ now < T + grace`, where `grace` is fixed in the plan (default 15 minutes).
  Outside that window it is recorded as `skipped` and never admitted later.
- A run succeeds only when the core reports finality for a successful operation
  and its receipt contains exactly one `Transfer(account, recipient, amount)`
  log emitted by the pinned token. A successful receipt alone is not the result.
- A finalized reverted operation marks the run `failed` and has consumed one
  onchain use. Failed runs are never retried automatically; the next scheduled
  occurrence proceeds normally.
- Independent workers contend through PostgreSQL claims with persisted
  generations, not process-local locks.

### Pause and revoke

- Pause closes admission for new runs and signing and accounts for in-flight
  signing admissions before reporting quiescence. Existing submitted work
  remains observable and may still execute.
- Resume rechecks valid, unexpired, unrevoked authority and reopens admission
  without catch-up runs.
- Revoke closes admission and invokes core revocation, retaining per-chain
  progress and install-approval invalidation. Deleting keys or records does not
  complete revocation.
- Cleanup attempts all required releases, preserves the primary failure, and
  retains custody needed for reconciliation. Pause, revoke, key deletion, and
  resource closure remain separate actions.

Activation verifies owner consent, signer recovery, the approved commitment, and
the exact chain/runtime profile. The profile uses the core's atomic
install-and-execute path, labeled ready for first execution, not installed.
Installation evidence remains a separate chain-local fact.

### Session signer custody

Each deployment's secp256k1 key is generated at deployment preparation and
stored sealed with a sealing key supplied explicitly to the signer process
(an environment-provided key in local development). A missing or wrong sealing
key makes the signer unavailable: it never creates a replacement key or signs.
A deployment's key reference cannot be used by another deployment.

## 6. Implementation sequence

Each numbered stage has one delivery gate. Split protocol, server, and UI
changes into focused PRs inside a stage; merge tested prerequisites first.
Follow AGENTS.md scope and evidence rules without adding a review phase.

| Stage | Deliverable and owner | Smallest proof / blocking regression | Depends on |
| --- | --- | --- | --- |
| 1 | Protocol execution-key binding and intent record codec | Deterministic key/digest; changed input changes digest; malformed or unsupported version rejected | Baseline |
| 2 | SDK `executeKeyed` entry over existing publication hooks; PostgreSQL execution-intent store and its state machine | Forbidden intent transitions (§5) tested first; two workers using one key produce one operation; changed input conflicts; crash at boundaries 1–4 recovers without a send | 1 |
| 3 | Durable sealed per-deployment signer and headless Grant/context recovery | New processes recover the same public key and authority; missing sealing key yields neither a new key nor a signature; another deployment cannot use that signer | 1 |
| 4 | JSON spec, transfer action, pinned capability profile, enforcement report, deployment commitment codec | Exact calldata and policy; wrong recipient/amount/selector/token rejected; commitment changes with action/input/chain/signer; accepted contract path proved on Anvil | 1 |
| 5 | Deployment lifecycle and consent: 5a protocol consent schema, 5b server lifecycle, 5c native presentation | Forbidden deployment transitions (§5) tested first; reviewed commitment equals activated deployment; changed plan/signer requires fresh consent; mismatched readiness blocks activation | 3, 4 |
| 6 | Scheduler, worker, manual admission, result check, pause/resume, and revoke orchestration | Duplicate ticks and two workers run once; occurrence outside grace is skipped; uncertain submission blocks new work; reverted run fails without retry; pause/signing and revoke/execution races retain truthful state | 2, 5 |
| 7 | Status API, `examples/automation/`, and packed multi-process local proof | Full §7 gate | 6 |

Stage 2 is the first behavioral implementation. Stages 3 and 4 can proceed
independently once stage 1 is merged; they do not justify a generic runtime
layer.

Stage 5c shows the action, schedule, recipient, amount, expiry, operation count,
custody-only signer, and actual enforcement levels, built on the existing
consent and match-code behavior and phone design.

### Proposed first API surface

These routes are implementation targets, not existing endpoints. Apply the
existing client authorization to each resource and admission.

| Route | Purpose |
| --- | --- |
| `POST /automations/compile` | Normalize the spec and return plan, required authority, and enforcement report |
| `POST /automations/deployments` | Create an immutable candidate and public signer binding |
| `POST /automations/deployments/{id}/authorize` | Start/link existing owner consent; never accept a caller's claim of approval |
| `POST /automations/deployments/{id}/activate` | Verify consent/readiness and open admission |
| `POST /automations/deployments/{id}/runs` | Admit a manual occurrence with a required idempotency key |
| `GET /automations/deployments/{id}` | Authority, lifecycle, installation evidence, and next occurrence |
| `GET /automations/runs/{id}` | Run result plus referenced core operation evidence |
| `POST /automations/deployments/{id}/pause` | Close admission and report outstanding work |
| `POST /automations/deployments/{id}/resume` | Recheck valid authority and reopen admission without catch-up runs |
| `POST /automations/deployments/{id}/revoke` | Start/link core revocation and any required owner signature |

Existing HTTP authorization/decision routes continue to own the owner decision.
API credentials cannot enlarge a Grant.

## 7. Evidence and milestone acceptance

Use focused tests for each stage. Run PostgreSQL, Anvil, or Swift evidence only
where that stage crosses the corresponding boundary. Keep fixtures and local
transports as defaults; no paid or shared RPC is used by this milestone.

The final milestone gate must prove:

- One approved immutable deployment produces a scheduled fixed transfer through
  packed packages, the canonical permission path, and real local contracts.
- Two worker processes on independent PostgreSQL connections cannot create two
  executions for one occurrence.
- Killing and recreating processes at each crash boundary in §5 retains account,
  signer, nonce, operation identity, and intent state, and recovery submits zero
  additional operations.
- Receipt absence, provider failure, unreadable state, and a pre-finality reorg
  remain unresolved until the core obtains sufficient evidence.
- A run succeeds only when the pinned token's `Transfer` log and core finality
  agree; a reverted operation fails the run without retry.
- Wrong recipient/amount/target/selector, expiry, exhausted operation count, and
  a modified plan or signer cannot execute under the approved deployment.
- Pause prevents newly admitted execution; already submitted work remains
  visible. Finalized revocation prevents new execution, and consumed approvals
  cannot reinstall authority through the supported path.
- A fresh API and worker recover from PostgreSQL store adapters. Memory stores,
  copied live handles, direct database injection, or reusing a process do not
  prove restart behavior.
- Packed imports, public-surface checks, package types/builds, and the final
  repository gate pass. No package is published or production chain modified.
  The existing fixed `0.x.y` group remains intact.

## 8. Deferred work

These start only after the first workflow is proven. They are separate
deliverables, not prerequisites for the milestone gate.

| Increment | Scope and completion gate |
| --- | --- |
| YAML input | YAML as an encoding of the existing JSON spec using a bounded established parser; prove YAML/API compile to identical commitments. |
| Operator surfaces | `oaath automation …` CLI over the HTTP API, a minimal management screen, and a durable outbound event outbox with webhook delivery; repeated delivery keeps one event ID and never repeats execution. |
| Gas sponsorship | Paymaster-backed project budgets with reservations held while outcomes are unknown and settled from verified receipts, including reverted attempts. |
| Deployment replacement | Separate Automation identity above Deployments; replacement stops old admission, reconciles old work, and explicitly authorizes any overlap. |
| Trigger expansion | Cron/IANA timezones with explicit DST behavior, then authenticated incoming webhooks and finalized chain-event cursors. |
| Token budgets | Per-execution, aggregate, and fixed-window token limits in shared policy plus concrete contracts, with atomic enforcement across concurrent runs. |
| Swap action | Pinned token/router/spender/ABI versions; bound approval, recipient, deadline, and min output; explicit oracle/guard profile for price guarantees. |
| Stronger signing | A provider that independently validates the exact approved payload and policy before signing; custody-only providers stay labeled as such. |
| Native execution profiles | [EIP-8130](https://eips.ethereum.org/EIPS/eip-8130) and [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) in separate pinned devnets, extending authorization, identity, signing, evidence, and revocation together. |
| Cross-chain routes | Ordered steps with source finality, destination evidence, and chain-local budgets; no generic cross-chain DAG. |

### Deferred API consolidation decisions

Public functions should not depend on Kernel version, EntryPoint version, key
kind, or transport. Where entry points do the same job and differ only in
implementation, they become one entry point with optional settings. Four items
were deliberately kept as they are during the 2026-09-29 DevEx reviews. Revisit
each when the consolidation stack lands, and again at the release-candidate
boundary:

| Kept separate | Why | Revisit when |
| --- | --- | --- |
| `ownerOperator` vs `sessionOperator` (`packages/sdk/src/kernel/operator/`) | They change who holds authority (root validation vs a scoped permission), so the difference is semantic, not an implementation detail. AGENTS.md treats operator role as its own composition axis. | A consumer needs to choose authority at runtime from data, or a third authority kind appears. Then consider `operator({ authority?: "session" })` with the same two owners behind it. |
| EIP-5792 vs ERC-7836 handling in `oaathProvider` (`packages/sdk/src/provider/`) | These are the wallet RPC standards callers speak, and both already sit behind one provider entry. | Either standard is superseded, or adopters need to enable only one. Then consider an optional `standards` setting on `oaathProvider`. |
| `createOperationObserver` vs `createUserOperationObserver` (`packages/sdk/src/operation-observer.ts`, `@oaath/sdk/advanced`) | Both use the same inclusion and finality verification, but they carry different authority. `observeOperation` advances a journaled `Operation` through the operation state machine, including `dropped` and `superseded` results that free a lane. `observeReference` only reports receipt and finality evidence for a saved reference. It never creates or advances an `Operation`, and it never decides a retry, a replacement, or a lane release. | An adopter journal needs to advance its own `Operation` from a saved reference, or the reference observer gains a state transition. Then consider one `observe({ operation } \| { reference })` entry that keeps the two result types. |
| ERC-4337 naming of the prepared operation (`PreparedUserOperation`, `UnsignedUserOperationV07`, `prepareUserOperation`, `asViemUserOperation`, `parsePreparedUserOperation` on `@oaath/sdk/kernel`) | Every shipped route kind is ERC-4337 (#239), so the prepared operation is a UserOperation in practice. AGENTS.md forbids generalizing before a second released implementation exists. Review and execution evidence already use opaque route and implementation identity (#237). | A native execution profile (EIP-8130 or EIP-8141) is implemented. Then derive a transport-neutral prepared-operation type from both implementations and scope the UserOperation shape to the ERC-4337 route kinds. |

Pilot selection, production rollout, credentials, security review, SLA, pricing,
and release publication remain separate decisions at the release-candidate
boundary.
