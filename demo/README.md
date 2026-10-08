# @oaath/demo

The hosted OAAth demo dapp at <https://oaath-demo.taek.tech>: a static page
(`index.html`, `src/`) and the Cloudflare Worker in front of it (`worker/`). On
its own origin it walks through every OAAth flow against
<https://oaath.taek.tech> on Arbitrum Sepolia: login, inviting a member, a
session-key Grant (pending for a member until the root approves), a test call,
an owner operation, and revocation in the portal.

## Worker routes

| Route | Handling |
| --- | --- |
| `/`, `/callback`, `/assets/*` | The built page, GET/HEAD only, strict CSP (`connect-src` self and the issuer). |
| `/config.json` | Issuer, `OAATH_CLIENT_ID` and chain settings from Worker vars; `sponsored` when a key is set. |
| `/rpc/chain`, `/rpc/bundler` | Same-origin, allow-listed, per-IP budgeted JSON-RPC to `CHAIN_RPC_URL` / `BUNDLER_URL`. |
| `/paymaster/421614` | Same-origin ERC-7677 proxy to `PAYMASTER_URL?apikey=PIMLICO_API_KEY`; sponsors only the demo's own call. 503 without a key. |

Every upstream request is made once, with no fallback; a send without an answer
gets a bare 504 and is only observed afterwards. `pm_getPaymasterData` spends a
per-IP budget and one global budget (`SPONSOR_GLOBAL_LIMIT`, a single-key
Cloudflare rate limit, per minute). Set a daily or total cap in the Pimlico
sponsorship policy as well.

## Configure and deploy

```sh
bun run --filter @oaath/demo test         # Worker unit tests
bun run --filter @oaath/demo test:e2e     # relay binary, portal and demo Workers, Anvil, headless Chrome
cd demo && bunx wrangler@4.147.0 secret put PIMLICO_API_KEY   # optional: enables sponsorship
bun run --filter @oaath/demo deploy:check
cd demo && bunx wrangler@4.147.0 deploy
```

The OAuth client is registered once with `POST https://oaath.taek.tech/oauth/clients`
(`redirect_uris: ["https://oaath-demo.taek.tech/callback"]`); put its id in
`OAATH_CLIENT_ID` in `wrangler.jsonc`. Register again whenever the relay's
database is recreated. `PIMLICO_SPONSORSHIP_POLICY_ID` (optional var) is sent as
the ERC-7677 context.
