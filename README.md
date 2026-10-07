# OAAth managed DCA

A Rust API and a small TypeScript SDK for recurring onchain purchases. Create a
plan, obtain owner approval, read progress, pause/resume, and cancel with
confirmed onchain effects. The complete local proof runs real Kernel v4,
EntryPoint 0.9 and Uniswap v3 on Anvil with PostgreSQL persistence.

The API lives in `api/`; the public SDK is `sdk/`. A **private TypeScript
execution service** composes OAAth's existing Grant, signer and Operation
machinery. It is part of the API deployment, not a third public product. Cetane
provides ABI encoding and bounded chain reads. Moesi core verifies the pinned
factory bytecode through a read-only Cetane observer. OAAth owns every purchase
submission, lane and finality transition.

## Run locally

Install Bun 1.4.2, Rust through rustup, Foundry (`anvil`), PostgreSQL tools and
Tailscale. Exact dependency tarballs and Solidity artifacts are retained in
`vendor/`; installation does not publish packages or contact a public chain.

```sh
bun install --frozen-lockfile
bun dev
```

Startup builds the release API, starts owned local fixtures, discovers this
machine's Tailscale IP/MagicDNS name, preserves unrelated Serve mappings and
prints the verified tailnet URL. The API binds loopback port 4317; Tailscale
Serve forwards port 4317 inside the tailnet. The execution bridge (4318), local
owner fixture (4319) and PostgreSQL (55437) remain loopback-only. No filesystem
is served. `GET /health` is public; all `/v1` endpoints require an application
bearer token and exact Host/Origin checks. Browser preflight uses the configured
origin only.

Local configuration and randomly generated tokens/sealing keys are in
`.local/environment.json` (0600), excluded from Git. Use `scripts/run.mjs api`
or `scripts/run.mjs runtime` to recreate services against retained records.
Set `DCA_RELEASE=1` for the release API. The sealed custody key and PostgreSQL
records must survive service restarts together. Missing custody fails closed;
it never rotates the approved session signer.

A new fixture run uses a new local database and fresh keys. It does not delete
prior databases. Stopping services preserves plans and operation history.
The owner fixture is test infrastructure and auto-signs **only** its own local
wallet; it is never exposed through Tailscale or included in the public SDK.

## Integrate

See [the SDK guide](sdk/README.md) for the supplied approval flow and a complete
API example. `scripts/proof-support.ts` is the minimal consumer: it loads the
**packed** SDK, uses a durable SQLite approval journal, and drives the existing
OAAth owner path. Applications provide customer identity, UI and wallet access.

| HTTP operation | Result |
| --- | --- |
| `GET /v1/config` | Pinned deployment, tokens, scheduling and fee profile |
| `POST /v1/plans` | Create or recover an identical application/account-scoped key |
| `GET /v1/plans` | Up to 100 latest plans and retained progress |
| `GET /v1/plans/:id` | Status, reviewed terms, fees, setup/cancellation evidence |
| `POST /v1/plans/:id/authorize` | Pending owner review with exact typed data and setup calls |
| `POST /v1/plans/:id/approve` | Verify signed consent; active or pending setup confirmation |
| `GET /v1/plans/:id/runs?after=-1&limit=50` | Ordered execution history; maximum page size 100 |
| `POST /v1/plans/:id/pause` / `resume` | Stop admission or resume while still eligible |
| `POST /v1/plans/:id/cancel` | Close admission; return retained cancellation progress/calls |
| `POST /v1/plans/:id/refresh` | Queue bounded observation; no viewer-triggered chain polling |

Create input matches the SDK guide. Token amounts are decimal strings, normalized
to pinned base units before consent. A reused key with changed canonical inputs
returns 409. A signed approval contains `commitment`, `consentSignature`,
`permissionSignature`, and an optional owner setup operation reference.
The service confirms actual finalized setup independently of that reference.
Malformed or unsupported plans are rejected; application ownership is checked
on every lookup. Errors have sanitized codes; ambiguous HTTP outcomes must be
reconciled through retained status. Projection `asOf` is its read time, not a
claim of fresh chain evidence; chain evidence carries its own block identity.

## Execution and consent

The local profile is standard 6-decimal USDC to 18-decimal WETH, one Uniswap v3
pool at fee 3000, and two 8-decimal fixture price feeds with a one-hour freshness
limit. They are local price fixtures, not live market data. The executor computes
minimum output from both feeds and the approved basis-point reduction, checks
freshness and account balance deltas, and atomically consumes a successful slot.
Reverts leave the successful-slot marker unset. Fee-on-transfer, rebasing and
arbitrary tokens/routes are unsupported.

Each plan has a dedicated immutable executor. Its Grant permits only that
address and `execute(uint32)`. Owner setup deploys it and approves exactly the
input cap. The session cannot edit terms, choose a recipient or broaden
allowances. The recipient is the bound account. The factory code hash and
executor commitment are checked before activation. Economic changes require a
new plan and fresh consent.

Slots open at `startAt + slot * 86400` and close exclusively 900 seconds later.
The fixed end is the final slot's close. `maxRuns` means scheduled opportunities,
not guaranteed purchases. Missed and finalized-failed slots are not made up.
Account-paid gas has separately reviewed ceilings; service fees are zero. There
is no sponsorship. Pause is a service control; cancellation requires owner
transactions for executor stop, allowance removal and Grant revocation.
Already submitted operations remain observed, including after plan expiry.

PostgreSQL claims use `FOR UPDATE SKIP LOCKED`, generations and revisions. The
unique `(planId, slot)` reservation retains its input digest and exact core
operation identity **before publication and broadcast**. Recovery never turns
missing evidence, a lease expiry or a lost acknowledgement into permission to
send again. An intent with a missing or merely prepared core record remains
unresolved; it can require operator investigation and blocks later purchases.
Cleanup diagnostics are separate from primary operation results.

## Optimization and verification

Due-time indexes avoid polling idle plans. Status/history are database
projections; list projection uses one SQL query. Four execution loops share
bounded chain ports (concurrency 16, two transport attempts, eight-second
request timeout). A process-wide 20,000-method budget uses explicit ten-minute
windows; each additional worker process has its own budget. Observation backs
off to 60 seconds. Exhaustion defers jobs to the next window. Reads are never
served from a cache of settled chain evidence. No claim about live-provider
cost or latency follows from local measurements.

```sh
bun run check
cargo test                         # pure Rust tests; PostgreSQL cases are opt-in
DCA_TEST_DATABASE_URL=postgres://USER@127.0.0.1:55437/DATABASE \
  cargo test -- --include-ignored
cargo clippy --all-targets -- -D warnings
bun scripts/pack-consumer.mjs
bun scripts/refresh-fixture.ts     # only refreshes owned fixture prices
bun scripts/stop.mjs runtime
bun scripts/recovery-proof.ts      # kills after accepted broadcast, loses reply
bun scripts/run.mjs runtime        # keep running in another terminal
bun scripts/setup-recovery-proof.ts
bun scripts/negative-proof.ts
bun scripts/cancel-proof.ts
bun scripts/boundary-proof.ts      # kills after reservation, publication, inclusion
```

The recovery scripts intentionally stop/recreate local services; do not run
them concurrently with another proof. The boundary proof leaves deliberately
unresolved evidence for inspection. `bun scripts/measure.ts` measures the
release API with retained history; pause execution workers for isolated RPC
counts, then restart them. [Evidence](evidence/README.md) records exact checks
and local measurements. [Upstream prerequisites](upstream/README.md) preserve
canonical owners and the original checkout's unrelated changes.

Public-chain deployment, production custody, release-candidate security work,
webhooks, billing, sponsorship, arbitrary routes and a polished management UI
remain separate scope. This delivery is the complete **local product proof**.
