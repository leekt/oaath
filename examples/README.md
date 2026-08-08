# OAAth examples

Four runnable examples. Each one narrates what it is doing and exits non-zero on
any failure, so each doubles as its own smoke.

| Example | Shows |
| --- | --- |
| [browser/](browser) | connect → one all-chain grant → execute → revoke |
| [server/](server) | Fetch relay over `node:http`, PostgreSQL, auth and KMS ports |
| [phone/](phone) | pair an iPhone, push, consent screen, approve, code delivery |
| [all-chain/](all-chain) | approve before chain B exists, then materialize on B |

```sh
pnpm install
pnpm examples:check                                   # all four, from the repo root
pnpm --filter @oaath/examples example:browser         # one at a time
pnpm --filter @oaath/examples example:server
pnpm --filter @oaath/examples example:phone           # pairs with native/ios/Demo
pnpm --filter @oaath/examples example:all-chain       # needs Anvil
```

Only `all-chain` needs anything installed (Anvil, from
[Foundry](https://getfoundry.sh)); `examples:check` skips it and says so when
Anvil is absent. `browser` runs against injected chain facts by default and
against a real local chain with `OAATH_REQUIRE_ANVIL=1`. `phone` waits for a
real iPhone by default and drives itself with `OAATH_PHONE_SIMULATE=1` (which
is how `examples:check` runs it). Opt-in credentials for `phone` may live in a
git-ignored `examples/.env` (loaded when present; the real environment wins).

## Rules these examples follow

- They import `@oaath/protocol`, `@oaath/sdk`, and `@oaath/server` by their
  published specifiers only. No `src` path, no test helper, no internal module.
- Every deployment-owned capability is injected and visible in the example
  itself: there is no preset system and no hidden network default to hide behind.
- Anything a real deployment must replace carries a `REPLACE` comment.

`support/workspace-typescript.mjs` is the one piece of scaffolding: inside this
repository the `@oaath/*` specifiers resolve to TypeScript sources, so the run
scripts pass `--import ./support/workspace-typescript.mjs` to let Node resolve
them. An adopter installs the built packages and needs none of it.

## Not a CI gate

`pnpm examples:check` is deliberately **not** wired into CI. These examples are
documentation: they run against the workspace, so they cannot prove anything
about the published artifacts. The packed smokes own that evidence and do run in
CI:

```sh
pnpm check:public-surface
pnpm smoke:browser    # packed tarball consumer, golden path, realm recreation
pnpm smoke:extension  # packed MV3 extension, worker death, durable status recovery
pnpm smoke:server     # packed tarball consumer, relay round-trip, ./postgres
pnpm smoke:all-chain  # two local Anvil chains, one replayable owner approval
```

Run `pnpm examples:check` locally when you change a public surface, so the
documentation cannot drift away from the code it documents.
