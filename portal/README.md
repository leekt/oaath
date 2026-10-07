# @oaath/portal

The OAAth portal at <https://oaath.taek.tech>: a React SPA (`src/`) and the
Cloudflare Worker in front of it (`worker/`). The SPA is where a user signs in
with a wallet or passkey, manages accounts, members and policy templates,
reviews a dapp's login, Grant or owner operation, and, as an account root,
signs. All state lives in the [relay](../relay/README.md); the SPA signs with the
SDK's own preparation and refuses a relay request that differs from it.

## Worker routes

| Route | Handling |
| --- | --- |
| `/`, `/authorize`, `/accounts`, `/link/{id}`, `/requests/{id}`, `/assets/*` | The built SPA (`ASSETS`), GET/HEAD only, with a strict CSP. |
| `/oauth/*`, `/.well-known/*` | Forwarded to the relay; credential-free CORS for dapps on other origins. |
| `/portal/*` | Forwarded to the relay; same-origin only, with the session cookie (`Path=/portal`) passed both ways. |
| `/rpc/421614` | Same-origin, budgeted, read-only Arbitrum Sepolia reads for account import (`worker/rpc.ts`). |

Only allow-listed request headers reach the relay and bodies are capped. Client
registration, PAR, signer registration and sign-in challenges spend a per-IP
`WRITE_LIMIT` budget first.

## Bindings

| Binding | Kind | Purpose |
| --- | --- | --- |
| `RELAY` | Workers VPC service | The relay. |
| `ASSETS` | Static assets | The built SPA in `dist/`. |
| `RPC_LIMIT` | Rate limit | Per-IP budget for `/rpc/421614`. |
| `WRITE_LIMIT` | Rate limit | Per-IP budget for unauthenticated writes. |
| `RPC_UPSTREAM_421614` | Secret, optional | Replaces the public Arbitrum Sepolia endpoint; never logged. |

`wrangler.jsonc` declares them.

## Develop and deploy

```sh
bun run --filter @oaath/portal test        # build, then Worker and SPA tests
bun run --filter @oaath/portal test:e2e    # the relay binary, this Worker module, headless Chrome
bun run --filter @oaath/portal deploy:check
cd portal && bun run build && bunx wrangler@4.147.0 deploy
```

Deploying needs the owner's Cloudflare credentials. The relay is deployed
separately.
