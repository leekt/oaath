# @oaath/automation-server

A self-hostable automation service: one Node process with the HTTP API, the
scheduler and the executors, and PostgreSQL as its only dependency. It runs
declarative automations from [`@oaath/automation`](../automation) with Grants
it obtains as an ordinary OAuth client of an OAAth issuer.

```sh
npx @oaath/automation-server   # the `oaath-automation` bin; configure with the variables below
```

Run any number of replicas against one database. The schema is created on
first start; an older schema is refused and must be dropped and recreated
(there are no migrations).

## Configuration

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection URL. Required. |
| `AUTOMATION_SEAL_KEY` | 64 hex characters: the AES-256-GCM key sealing session keys and OAuth verifiers at rest. Required; keep it with the database. |
| `AUTOMATION_PUBLIC_URL` | The service's external base URL. The OAuth redirect URI is `<url>/v1/oauth/callback`. Required. |
| `AUTOMATION_LISTEN` | `host:port`; default `127.0.0.1:4317`. |
| `OAATH_ISSUER` | The OAAth issuer URL, e.g. `https://oaath.taek.tech`. Required. |
| `OAATH_CLIENT_ID` | This service's client, registered at the issuer with the redirect URI above. Required. |
| `AUTOMATION_APPLICATIONS` | Comma-separated `id:sha256hex` application credentials (SHA-256 of each bearer token). Required. |
| `AUTOMATION_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the API and to be `returnTo` targets. |
| `AUTOMATION_DEFINITIONS` | Comma-separated JSON files, each one definition or an array. Required. |
| `AUTOMATION_RPC_URL_<chainId>` | Chain RPC for every chain a definition names. Required. |
| `AUTOMATION_BUNDLER_URL_<chainId>` | ERC-4337 bundler for that chain. Required. |
| `AUTOMATION_PAYMASTER_URL_<chainId>` | Optional ERC-7677 paymaster; operations are self-funded without it. |
| `AUTOMATION_PAYMASTER_API_KEY_<chainId>` | Optional key for that paymaster, sent as the ERC-7677 context `{ "apiKey": ... }` (as [paymaster-rs](https://github.com/leekt/paymaste_rs) accepts it) instead of `{}`. Requires the paymaster URL. |
| `AUTOMATION_RELAY_PAYS_GAS_<chainId>` | Optional `true` when that chain's bundler pays gas itself ([bundle_rs](https://github.com/zerodevapp/bundle_rs) fast mode): operations carry zero fees and need no funds or paymaster. Refused together with a paymaster URL. |
| `AUTOMATION_MAX_OPEN_SLOTS` | Occurrences of one plan that may be open at once, each on its own nonce lane; default 4. |
| `AUTOMATION_RPC_BUDGET`, `AUTOMATION_BUNDLER_BUDGET`, `AUTOMATION_PAYMASTER_BUDGET` | Hard request budgets per window; defaults 3000, 300 and 100. |
| `AUTOMATION_BUDGET_WINDOW_SECONDS` | Budget window; default 600. Exhausted work waits for the next window. |

Logs never include URLs, tokens, keys or provider errors.

## Execution

```text
plan  draft -> awaiting_consent -> authorized -> active <-> paused
      active|paused -> completed | expired; open plans -> cancelling -> cancelled
      authorized -> active once setup is included and successful (not final)
      authorized|active|paused -> failed when setup fails, reverts or drops
      authorized -> expired (setup_not_included) at the Grant end
run   due -> claimed -> prepared -> submitted -> observed -> finalized
      terminal: finalized | failed | skipped
```

- Slot windows are the plan's terms: slot N opens at `startAt + N*every` and
  closes `grace` later, exactly as the setup's on-chain plan and the Grant
  policy were signed, capped at the Grant end. Activation gates admission
  without moving a window: slot N is due at max(its opening, activation) and is
  skipped once its window closes, or at once if it opens after the Grant ends.
  An authorized plan never expires before the Grant end while it waits for its
  setup.
- Each run has one Kernel nonce lane, assigned once at admission: setup and
  cancel use the default lane; occurrence slot N uses lane N + 1 when the plan
  has a setup (still observed on lane 0 until final), else lane N. One open run
  per plan and lane (a unique index), so one unresolved operation per Grant,
  chain and lane.
- A slot does not wait for an earlier operation's finality: once one of the
  plan's operations is included (the permission install is on chain), up to
  `AUTOMATION_MAX_OPEN_SLOTS` occurrences run side by side. Before that, slots
  open one at a time. A slot that cannot open is skipped once its window
  closes. Cancel waits until no run is open.
- Runs are claimed with `SELECT … FOR UPDATE SKIP LOCKED` and a lease; every
  write is fenced by the claim's generation.
- The calls are persisted before sending. The SDK journals each operation
  before signing it, and the same transaction records its hash and nonce on the
  run; an identity no prepared run claims is refused.
- A run with an operation hash is only ever observed again. A timeout, missing
  receipt, drop or unreadable observation never resubmits.
- Session keys are generated per user (default) or per application
  (`POST /v1/application {"keyScope":"application"}`) and sealed at rest.

Authorization pushes an `oaath_grant` request (PKCE, the session key as the
Grant's signer, the policy derived from the plan) to the issuer. The account
root approves it in the portal; the first operation installs the permission in
enable mode. Cancellation stops admission and runs the definition's cancel
calls; uninstalling the permission on chain remains the account root's action
in the portal.

## Test

```sh
bun run --filter @oaath/automation-server test       # unit and PostgreSQL suites
bun run --filter @oaath/automation-server test:e2e   # relay + two replicas + Anvil
```

The PostgreSQL suites start a throwaway local cluster (or use
`OAATH_TEST_POSTGRES_URL`) and skip without PostgreSQL binaries unless
`OAATH_REQUIRE_POSTGRES=1`. The end-to-end run builds the relay with cargo,
approves a [DCA plan](../../examples/dca) through the portal API as its account
root, and checks that the setup and two due occurrences each send exactly once,
with finality held so that the plan activates on setup inclusion, a held
operation is observed repeatedly, and the second occurrence comes due while the
first is included but not final. Its bundler is a
loopback fixture over `EntryPoint.handleOps`; no public network is contacted.
