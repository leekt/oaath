# @oaath/demo

The hosted OAAth demo dapp at <https://oaath-demo.taek.tech>: a static page
(`index.html`, `src/`) and the Cloudflare Worker in front of it (`worker/`). On
its own origin it walks through every OAAth flow against
<https://oaath.taek.tech> on Arbitrum Sepolia: login, inviting a member, a
session-key Grant (pending for a member until the root approves), a test call,
an owner operation, backend automation through
[`@oaath/automation`](../packages/automation), and revocation in the portal.

## Worker routes

| Route | Handling |
| --- | --- |
| `/`, `/callback`, `/assets/*` | The built page, GET/HEAD only, strict CSP (`connect-src` self and the issuer). |
| `/config.json` | Issuer, `OAATH_CLIENT_ID` and chain settings from Worker vars; `sponsored` when the `BUNDLER` binding is set. |
| `/rpc/chain` | Same-origin, allow-listed, per-IP budgeted JSON-RPC to `CHAIN_RPC_URL`. |
| `/rpc/bundler` | Same-origin, allow-listed, per-IP budgeted ERC-4337 JSON-RPC to bundle_rs through the `BUNDLER` VPC binding. `eth_sendUserOperation` and `eth_estimateUserOperationGas` accept only the demo's own call through EntryPoint 0.9. 503 without the binding. |
| `/automation/session` | Same-origin, per-IP budgeted: verifies the login's id_token (issuer JWKS, this client) and creates a one-hour session at `AUTOMATION_URL` with the `AUTOMATION_APP_TOKEN` secret. 503 without it. |

Every upstream request is made once, with no fallback; a send without an answer
gets a bare 504 and is only observed afterwards. `eth_sendUserOperation` also
spends the per-IP `SEND_LIMIT` budget.

Gas is paid by [bundle_rs](https://github.com/zerodevapp/bundle_rs) in its
default fast mode: the page builds its chain ports with `relayPaysGas`, so every
operation carries zero fees and the relay's executor pays chain gas. No account
is funded and no paymaster is used (Pimlico, ZeroDev and Alchemy paymasters do
not support EntryPoint 0.9, which Kernel v4 accounts use). bundle_rs listens on
`127.0.0.1:4337` on the VM, so the Worker reaches it through a Workers VPC
service. Create that service and put its id in `vpc_services[BUNDLER].service_id`
in `wrangler.jsonc` (it ships as the placeholder `BUNDLER_VPC_SERVICE_ID`).

## Configure and deploy

```sh
bun run --filter @oaath/demo test         # Worker unit tests
bun run --filter @oaath/demo test:e2e     # relay binary, portal and demo Workers, Anvil, headless Chrome
bun run --filter @oaath/demo deploy:check
cd demo && bunx wrangler@4.147.0 deploy
```

The OAuth client is registered once with `POST https://oaath.taek.tech/oauth/clients`
(`redirect_uris: ["https://oaath-demo.taek.tech/callback"]`); put its id in
`OAATH_CLIENT_ID` in `wrangler.jsonc`. Register again whenever the relay's
database is recreated.

When bundle_rs requires client authentication, put its key with
`wrangler secret put BUNDLER_API_KEY`. The Worker sends it to the bundler only,
as `x-api-key`, and never forwards a client's key. Without it, sends and
estimates are refused with RPC `-32001`.

Automation runs on the service at `AUTOMATION_URL`, configured with
[`automation/demo-ping.automation.json`](automation/demo-ping.automation.json)
in its `AUTOMATION_DEFINITIONS` and `https://oaath-demo.taek.tech` in its
`AUTOMATION_ALLOWED_ORIGINS`. Put the demo's application token there (as
`demo:<sha256>`) and here with `wrangler secret put AUTOMATION_APP_TOKEN`. The
page creates and watches plans at the service directly with the session token.
