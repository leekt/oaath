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
| [oauth-login/](oauth-login) | Login with OAAth from a static page through the live portal |
| [oauth-grant-demo/](oauth-grant-demo) | live Arbitrum Sepolia: portal-approved Grant, then one enable-mode covered call (opt-in) |

```sh
bun install
bun run examples:check                                   # from the repo root
bun run --filter @oaath/examples example:browser         # one at a time
bun run --filter @oaath/examples example:server
bun run --filter @oaath/examples example:phone           # pairs with native/ios/Demo
bun run --filter @oaath/examples example:all-chain       # needs Anvil
bun run --filter @oaath/examples example:oauth-login     # open http://localhost:5174
```

`oauth-login` signs in against `https://oaath.taek.tech` by default
(`OAATH_ISSUER` overrides it, `OAATH_CLIENT_ID` skips the one-time client
registration). It must run on `http://localhost`, a redirect origin the issuer
accepts for development.

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

`bun run examples:check` runs locally. CI separately runs the phone service workflow
and the native phone suite. Workspace examples demonstrate composition; packed
smokes own evidence about published artifacts:

```sh
bun run check:public-surface
bun run smoke:browser    # packed tarball consumer, golden path, realm recreation
bun run smoke:extension  # packed MV3 extension, worker death, durable status recovery
bun run smoke:server     # packed tarball consumer, relay round-trip, ./postgres
bun run smoke:all-chain  # two local Anvil chains, one replayable owner approval
```

Run `bun run examples:check` locally when you change a public surface, so the
documentation cannot drift away from the code it documents.

## Live Grant demo on Arbitrum Sepolia

`oauth-grant-demo` is the one example that touches a public network, so it runs only
with an explicit opt-in:

```sh
OAATH_LIVE=1 bun run --filter @oaath/examples example:oauth-grant-demo
# open http://localhost:5175
```

1. **Request permission** opens the OAAth portal at `https://oaath.taek.tech`: sign in
   with your wallet or passkey, choose or create an account, and approve the Grant with
   the account root. The policy allows only zero-value calls with selector `0x12345678`
   to `0x…dead` (no code, no funds), at most twice per chain, for one hour.
2. The page shows the counterfactual account and how much Arbitrum Sepolia ETH to send
   it for gas (4.1M gas at three times the current gas price; there is no paymaster).
   **Check balance** reads it once.
3. **Send covered call** sends one UserOperation: the factory deploys the account, enable
   mode installs the permission, and the call executes. The page shows the
   UserOperation hash, the transaction hash and its Arbiscan link, and observes until
   the RPC's `finalized` tag covers it (Arbitrum finality can take tens of minutes).
   A reload resumes the Grant and keeps observing the stored operation.

The page reaches the chain only through the demo server's `/rpc/chain` and
`/rpc/bundler`. That server forwards to exactly one RPC
(`https://sepolia-rollup.arbitrum.io/rpc`) and one bundler
(`https://public.pimlico.io/v2/421614/rpc`), with no fallback and an allow-listed method
set. It enforces a hard budget (800 requests by default, `OAATH_MAX_REQUESTS`), a
concurrency cap, a 15-second request timeout, and a time cap (45 minutes,
`OAATH_TIME_CAP_MINUTES`). When the budget or the time cap is spent, it stops forwarding
for good. A request that times out is never repeated, and the SDK keeps an unanswered
send uncertain and only observes it. Logs name methods and counts, never URLs, bodies or
keys. `OAATH_RPC_URL` and `OAATH_BUNDLER_URL` override the endpoints and stay on the
server; only their origins are printed. The portal end-to-end test rehearses the same
flow on a local Osaka Anvil (chain 421614) with a fixture bundler, and no test or CI job
runs this demo.
