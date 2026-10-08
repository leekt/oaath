# @oaath/dca-app

The hosted DCA example at <https://dca.taek.tech>: a static page (`index.html`,
`src/`) and the Cloudflare Worker in front of it (`worker/`). On Arbitrum
Sepolia a person:

1. signs in with OAAth (<https://oaath.taek.tech>);
2. sets a small plan: amount per buy (test tUSD), number of buys, interval;
3. approves it once in the OAAth popup;
4. watches the hosted automation service make each buy, with per-buy state,
   Arbiscan links and token balances.

The service holds the plan's session key and sends every operation through its
gas-paying bundler; this app never signs or submits. The market and the
definitions are in [`examples/dca`](../examples/dca): the plan's setup mints its
own test tUSD budget, approves the shared `DcaExecutor`, and opens the plan;
each buy swaps tUSD for tETH on Uniswap v3.

## Worker routes

| Route | Handling |
| --- | --- |
| `/`, `/callback`, `/assets/*` | The built page, GET/HEAD only, strict CSP (`connect-src` self, the issuer and the service). |
| `/config.json` | Issuer, `OAATH_CLIENT_ID`, chain and the service URL from Worker vars; `automation: null` without the app credential. |
| `/rpc/chain` | Same-origin, per-IP budgeted, read-only JSON-RPC (`eth_chainId`, `eth_blockNumber`, `eth_call`) to `CHAIN_RPC_URL`, for balances. |
| `/automation/session` | Same-origin, per-IP budgeted: verifies the login's id_token (issuer JWKS, this client) and creates a one-hour session at the service with the `AUTOMATION_APP_TOKEN` secret, through the `AUTOMATION_SERVICE` binding. 503 without the secret. |

The page offers every definition the service loads whose id starts with
`dca.arbsep.` (one per interval), so the market addresses and limits live only
in the service's definitions.

## Deploy

In order:

1. **Market.** `examples/dca/deploy-arbsep.sh` (see
   [its README](../examples/dca/README.md#hosted-market-on-arbitrum-sepolia)).
   It writes `examples/dca/dca-arbsep.deployed.json`.
2. **Automation service.** Copy that file to the VM, append its path to
   `AUTOMATION_DEFINITIONS`, add `https://dca.taek.tech` to
   `AUTOMATION_ALLOWED_ORIGINS`, and add the app credential to
   `AUTOMATION_APPLICATIONS` as `dca:<sha256 hex of the token>`
   (`AUTOMATION_RELAY_PAYS_GAS_421614=true` stays set). Restart the service.
   Generate the token with `openssl rand -hex 32` and hash it with
   `printf %s "$TOKEN" | shasum -a 256`.
3. **OAuth client.** Register once and put the returned `client_id` in
   `OAATH_CLIENT_ID` in `wrangler.jsonc`:

   ```sh
   curl -sS https://oaath.taek.tech/oauth/clients -H 'content-type: application/json' \
     -d '{"client_name":"OAAth DCA","redirect_uris":["https://dca.taek.tech/callback"]}'
   ```

   Register again whenever the relay's
   database is recreated.
4. **Worker secret.** `cd dca && bunx wrangler@4.147.0 secret put AUTOMATION_APP_TOKEN`
   with the same token.
5. **Worker.** `bun run build` at the root (wrangler bundles the built
   `@oaath/automation`), then `cd dca && bunx wrangler@4.147.0 deploy`.

```sh
bun run --filter @oaath/dca-app test        # Worker, plan form, run rows, definitions
bun run --filter @oaath/dca-app typecheck
bun run --filter @oaath/dca-app deploy:check
```
