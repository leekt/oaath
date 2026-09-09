# OAAth examples

The [phone service](phone) is the reference workflow: personal or team operation,
one owner phone, bounded jobs on configured chains, and onchain revocation.
The other examples demonstrate individual capabilities.

| Example | Shows |
| --- | --- |
| [browser/](browser) | connect → one all-chain grant → execute → revoke |
| [server/](server) | Fetch relay over `node:http`, PostgreSQL, auth and KMS ports |
| [phone/](phone) | personal/team service, canonical phone consent, two-chain jobs, recovery and revocation |
| [all-chain/](all-chain) | approve before chain B exists, then materialize on B |

```sh
pnpm install
pnpm examples:check                                   # from the repo root
pnpm --filter @oaath/examples example:browser         # one at a time
pnpm --filter @oaath/examples example:server
pnpm --filter @oaath/examples example:phone           # pairs with native/ios/Demo
pnpm --filter @oaath/examples example:all-chain       # needs Anvil
```

`phone` and `all-chain` require Anvil from
[Foundry](https://getfoundry.sh). The check skips these chain examples when Anvil
is absent. `browser` uses injected chain facts by default and a real local chain
with `OAATH_REQUIRE_ANVIL=1`. `phone` waits for a real iPhone by default;
`OAATH_PHONE_SIMULATE=1` drives personal and team workflows across two local
chains with a P-256 fixture. Optional APNs configuration may live in a gitignored
`examples/.env`; the real environment wins.

## Rules these examples follow

- They import `@oaath/protocol`, `@oaath/sdk`, and `@oaath/server` by their
  published specifiers only. No `src` path or internal module. Ephemeral demos
  use the exported in-memory adapters.
- Every deployment-owned capability is injected and visible in the example
  itself: there is no preset system and no hidden network default to hide behind.
- Anything a real deployment must replace carries a `REPLACE` comment.

`support/workspace-typescript.mjs` is the one piece of scaffolding: inside this
repository the `@oaath/*` specifiers resolve to TypeScript sources, so the run
scripts pass `--import ./support/workspace-typescript.mjs` to let Node resolve
them. An adopter installs the built packages and needs none of it.

## Evidence

`pnpm examples:check` runs locally. CI separately runs the phone service workflow
and the native phone suite. Workspace examples demonstrate composition; packed
smokes own evidence about published artifacts:

```sh
pnpm check:public-surface
pnpm smoke:browser    # packed tarball consumer, golden path, realm recreation
pnpm smoke:extension  # packed MV3 extension, worker death, durable status recovery
pnpm smoke:server     # packed tarball consumer, relay round-trip, ./postgres
pnpm smoke:all-chain  # two local Anvil chains, one replayable owner approval
```

Run `pnpm examples:check` locally when you change a public surface, so the
documentation cannot drift away from the code it documents.
