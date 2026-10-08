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
gas-paying bundler. The market and the definitions are in
[`examples/dca`](../examples/dca): the plan's setup mints its own test tUSD
budget, approves the shared `DcaExecutor`, and opens the plan; each buy swaps
tUSD for tETH on Uniswap v3.

**Mint 1,000 tUSD.** After sign-in, one button mints test tUSD into the
account without a wallet prompt. tUSD's `mint` is permissionless, so the page
sends one zero-fee ERC-4337 operation, `tUSD.mint(account, 1000e6)`, from a
throwaway Kernel v4 account of a key it generates and keeps in
`localStorage` (the first operation deploys it), through `/rpc/bundler`.

## Worker routes

| Route | Handling |
| --- | --- |
| `/`, `/callback`, `/assets/*` | The built page, GET/HEAD only, strict CSP (`connect-src` self, the issuer and the service). |
| `/config.json` | Issuer, `OAATH_CLIENT_ID`, chain and the service URL from Worker vars; `automation: null` without the app credential; `mint: null` without the `BUNDLER` binding or `TUSD_TOKEN`. |
| `/rpc/chain` | Same-origin, per-IP `RPC_LIMIT`, allow-listed reads to `CHAIN_RPC_URL`, for balances and the mint account. |
| `/rpc/bundler` | Same-origin, per-IP `RPC_LIMIT`, plus `SEND_LIMIT` per send, to bundle_rs (relay-paid) over the `BUNDLER` VPC binding. Estimates and sends only one zero-value `TUSD_TOKEN.mint(any, 1000e6)` through EntryPoint 0.9; receipts pass through. 503 without the binding or token. |
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
   with the same token, and `secret put BUNDLER_API_KEY` with the bundle_rs
   client key (sent to the bundler only, as `x-api-key`; without it the bundler
   refuses the mint with RPC `-32001`).
5. **Worker.** `bun run build` at the root (wrangler bundles the built
   `@oaath/automation`), then `cd dca && bunx wrangler@4.147.0 deploy`.

```sh
bun run --filter @oaath/dca-app test        # Worker, plan form, run rows, definitions
bun run --filter @oaath/dca-app typecheck
bun run --filter @oaath/dca-app deploy:check
```
