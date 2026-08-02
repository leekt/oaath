# AGENTS.md

These are OGP's authoritative repository-specific rules. Other documents may
point here but must not redefine them.

## Core principles

- Use `pnpm` and repository-owned scripts.
- All releases remain `0.x.y` until a separate explicit 1.0 decision.
- Before 1.0, do not preserve backward compatibility by default.
- Do not preserve old APIs, packages, schemas, databases, or artifacts from
  `leekt/deployer`.
- Delete obsolete readers, writers, aliases, wrappers, forwarding packages,
  fallback branches, compatibility barrels, and in-place upgrade helpers
  instead of recreating them.
- Persisted schemas and security artifacts still require explicit versioning.
- Choose the simplest implementation that fully meets current requirements.
- Prefer established, well-maintained libraries over custom implementations.
- Keep default APIs focused on the adopter workflow, not speculative failures.
- OGP never depends on Moesi. Consumers use a released package or an exact
  local tarball, never git dependencies or cross-repository source imports.
- Kernel/ZeroDev is the opinionated first runtime. Do not build a generic
  provider framework without a second real runtime.

## Roles and merge authority

Every non-trivial PR has separate roles:

- **Coordinator/implementer:** may edit, test, commit, push, and merge.
- **Independent reviewer:** uses fresh context and is read-only; it must not
  edit, commit, push, or merge the candidate.

The implementer may merge only after an independent reviewer accepts the exact
current head. Any code or test change invalidates the review. If no independent
reviewer is available, an explicit repository-owner override is required.
Use a second reviewer for cryptography, authority, durable state, submission or
retry safety, release authorization, or destructive lifecycle changes.

Allowed verdicts:

```text
ACCEPTED
CHANGES_REQUIRED
```

Non-blocking follow-ups must not expand the current PR.

## Start with the invariant owner

Before coding, state:

1. the smallest user outcome or invariant;
2. the function, type, codec, store, or state machine that owns it;
3. the smallest change that proves it;
4. the accepted-path proof and key negative regression;
5. deferred work and evidence not run.

Fix the owner, not repeated callers. A child PR must not be the first branch to
repair correctness owned by its parent.

## Model state before coding

For lifecycle, persistence, retry, concurrency, cleanup, lease, nonce,
submission, observation, finality, queue, or release work, write:

```text
state and owner
persisted evidence
resource occupied?
retry positively safe?
allowed and terminal transitions
crash or reload behavior
cleanup owner after partial failure
```

Write the important forbidden-transition tests before broad implementation.

## Trust boundaries

Adversarial validation belongs at wire/RPC input, durable storage, runtime or
adapter output, cryptographic artifacts, and caller-injected capabilities.
Capture each boundary once into an exact, owned, immutable representation.
Internal typed code should consume it instead of repeating hostile-object
validation everywhere.

Machine decisions use structured codes, statuses, and discriminants, never
`Error.message` or diagnostic prose.

## Reviewable scope

One PR proves one primary outcome or invariant. Split independent browser,
server, database, native, contract, protocol, release, and UI hypotheses.
More than 25 non-generated files, 2,000 non-generated added lines, or two major
trust boundaries requires an exact-head repository-owner exception.

Stacked PRs remain independent review units. Merge the accepted parent before
treating it as proven behavior. Do not merge first and review afterward.

## Tests and evidence

Use the smallest evidence that proves the change:

- **Tier 1:** focused tests, typecheck/build, lint, generated output, and diff
  checks.
- **Tier 2:** packed consumer and the relevant local Chromium, PostgreSQL,
  Anvil, Forge, reload, or cross-package path.
- **Tier 3:** full repository gate, coverage, all integrations, surfaces,
  bundles, and audits at the final stack or release-candidate boundary.

Do not run Tier 3 for every child or corrective PR. Public claims use documented
exports and packed artifacts. Reload claims recreate every in-memory instance.
Protocol claims use the accepted contract path. Cleanup tests fail effects
independently and together. Persistence tests use independent connections.
Observation retry submits zero new operations. Property and fuzz tests stay
pure and local.

A demo runtime, permissive fake, source import, direct storage injection, or
finalizing before recreation does not prove the claimed path.

## Authority, operation, and cleanup

Grant authority and individual Operation state are separate. An installed
permission does not prove that a particular operation was included.

Preserve exact operation IDs and submission evidence when observation fails.
Retry observation without resubmitting. One unresolved lane is allowed per
`(grantId, chainId)` in the first release; distinct chains may proceed
independently and may never borrow one another's evidence.

Keep effects explicit:

- `close` releases runtime resources;
- `signOut` revokes relay or application authentication;
- `forgetLocal` deletes local key or grant data;
- `revoke` submits onchain revocation;
- observation and finality confirm authoritative state.

Cleanup is secondary. Attempt every required cleanup, preserve the canonical
operation error, retain cleanup failures only as suppressed diagnostics, and
keep unfinished cleanup retryable. Mark an effect complete only after success.

## External services and RPC budgets

Automated tests must not contact paid or shared RPCs by default. Use fixtures,
owned transports, recorded responses, or local Anvil.

The presence of `INFURA_*`, `ALCHEMY_*`, `PARITY_RPC_URL`,
`ZERODEV_PROJECT_ID`, or a generic RPC variable is not consent to spend it.
Normal gates must scrub live-provider variables unless one explicit
repository-owned live-test flag is set.

Every live-network suite must use a dedicated low-quota credential, require
explicit opt-in, bound requests, concurrency, retries, polling, and time,
disable hidden fallback, redact credentials, and abort when its budget is
exhausted.

Never put live RPC calls in unit, coverage, fuzz, property, docs, generated API,
pre-push, or broad repository tests. Accidental external access or an unbounded
provider loop is a blocker.

## Security

Never put private keys, signatures, session material, bearer tokens, approval
artifacts, credential-bearing URLs, request bodies, or raw provider errors in
logs, fixtures, diagnostics, PR text, or retained evidence.

Fail closed on unreadable, ambiguous, malformed, contradictory, or unsupported
evidence. `unreadable` is not `absent`, and a receipt does not verify itself.
Bind chain, EntryPoint, account, permission, signer, nonce, operation,
transaction, block, and finality evidence at the owner that claims it.

## Merge protocol

The implementer may merge when the exact head is independently accepted, no
blocker remains, Tier 1 and applicable Tier 2 evidence passed, evidence limits
are accurate, and no unreviewed conflict resolution is introduced.

PR bodies stay concise: outcome, invariant owner, state model when applicable,
smallest change, focused proof, and evidence limits.
