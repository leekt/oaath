# oaath-relay

The OAAth issuer: OAuth 2.0 / OpenID Connect endpoints, the portal API, and the
durable registry of signers, accounts, memberships, policy templates and Grants.
`crates/oaath-protocol` is the Rust mirror of `@oaath/protocol`; its fixtures
in `fixtures/` are generated from the TypeScript owner
(`bun run fixtures:protocol`) and must match.

## Run

```sh
cargo run -p oaath-relay                  # memory store on 127.0.0.1:8787
cargo run -p oaath-relay -- --create-schema   # with OAATH_POSTGRES_URL: create the schema first
```

| Variable | Meaning |
| --- | --- |
| `OAATH_LISTEN` | Listen address; default `127.0.0.1:8787`. |
| `OAATH_POSTGRES_URL` | PostgreSQL store; the memory store when unset. |
| `OAATH_KMS_KEY` | 64 hex characters: the AES-256-GCM key sealing stored artifacts. Required. |
| `OAATH_ISSUER` | The issuer URL (no trailing slash). Enables `/oauth/*`, discovery and the portal transaction routes. |
| `OAATH_ID_TOKEN_KEY` | Path to the ES256 (P-256) PKCS#8 PEM id_token signing key; required with `OAATH_ISSUER`. |
| `OAATH_ID_TOKEN_KID` | Optional `kid`; defaults to the key's RFC 7638 thumbprint. |
| `OAATH_RPC_421614` | Optional JSON-RPC URL for chain 421614, read only to prove an imported account's root and to read a revocation's permission state; without it imports and revocations are refused. |
| `OAATH_WRITES_PER_MINUTE` | Hard budget of public writes (client and signer registration, PAR, sign-in challenges) per route and client address per minute; default 30. The client address is the `x-oaath-client-ip` the portal Worker sets from `cf-connecting-ip`; requests without it come from inside the relay's network and are not budgeted. Over budget answers 429 `relay_rate_limited`. |
| `OAATH_BUNDLER_421614` | Optional bundler JSON-RPC URL for chain 421614 (Pimlico: it uses `pimlico_getUserOperationGasPrice`). It estimates and submits root-signed revocations, one attempt each, within a budget of 32 bundler requests per revocation, and never resubmits. Without it no revocation is prepared. |

`--create-schema` creates the current PostgreSQL schema and fails if any object
already exists. There are no migrations: an older schema is recreated. Logs
never include codes, artifacts, verifiers, tokens, keys, request bodies, the
RPC URL or the bundler URL.

The developer console at `/developers` uses `oaath.oauth-client-record/v2` and
PostgreSQL schema `oaath.relay-postgres-schema/v2`. Deploy the relay and portal
Worker together. Recreate older relay state and re-register clients (including
Keyline); there is no in-place upgrade. Console apps belong to the signer that
creates them. Public `/oauth/clients` registrations have no managing signer and
cannot be claimed through the console.

## Endpoints

The OAuth surface is listed in the [repository README](../README.md#dapp-api).
The portal API is same-origin only; a session is a cookie set by sign-in.

| Route | Purpose |
| --- | --- |
| `GET /portal/clients`, `POST /portal/clients`, `PUT /portal/clients/{id}` | List, create and edit the authenticated signer's OAuth apps. Metadata uses the public registration shape; the owner is session-derived and immutable. |
| `POST /portal/signers` | Register a wallet or passkey credential profile (idempotent). |
| `GET /portal/signers/by-credential/{id}` | Identify a passkey's signer. |
| `POST /portal/sessions/challenge`, `POST /portal/sessions`, `DELETE /portal/sessions` | Sign in with a SIWE signature or WebAuthn assertion; sign out. |
| `GET /portal/signers/{id}/accounts` | The signed-in signer's accounts and roles. |
| `POST /portal/accounts` | Create a factory-derived account (idempotent per `creation_key`). |
| `POST /portal/accounts/import` | Import an existing Kernel account after proving its root on chain. |
| `POST /portal/links`, `GET /portal/links/{id}`, `POST /portal/links/{id}/prepare`, `POST /portal/links/{id}/{approve,reject}` | A new signer asks to join an account; the root decides. |
| `/portal/accounts/{id}/policies[/{template}]` | The root's policy templates (GET, POST, PUT, DELETE). |
| `GET /portal/accounts/{id}/members`, `POST .../members/{signer}/{suspend,restore}`, `DELETE .../members/{signer}` | Membership management. |
| `POST /portal/accounts/{id}/members/{signer}/grants[/prepare]` | The root assigns a Grant to a member. |
| `GET /portal/accounts/{id}/requests`, `GET /portal/requests/{id}`, `POST /portal/requests/{id}/{prepare,approve,reject}` | Members' pending Grant requests and the root's decision. |
| `GET /portal/grants/{id}` | A member's view of its Grant. |
| `GET /portal/transactions/{id}`, `POST .../prepare`, `POST .../decision`, `GET .../redirect` | One pushed authorization: the root prepares and signs, the decision issues the code, and the redirect is recoverable. |

## Test

```sh
cargo test --workspace
scripts/test-postgres.sh   # the PostgreSQL store against a throwaway local cluster
```

The portal's end-to-end test (`bun run --filter @oaath/portal test:e2e`) and
`bun run smoke:extension` run the built binary on loopback.
