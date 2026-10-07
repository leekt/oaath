# Automation

A managed onchain automation product in two public parts: a **Rust API** and a
**TypeScript SDK**, including an embeddable React + shadcn/ui creator. Customers
specify and approve their automations. Applications integrate identity and a
wallet; the service owns scheduling, scoped execution, recovery and history.

DCA is the first supported recipe and the example application, not the entire
product API. `dca.v1` buys one pinned ERC-20 with another daily, with a fixed
input, verified price bounds, a bounded allowance and a fixed number of
opportunities. Missed and finalized-failed opportunities are skipped.

## Integrate

[The short integration guide](sdk/README.md) is the starting point for humans
and coding agents. [llms.txt](llms.txt) supplies the compact integration contract;
[OpenAPI](api/openapi.json) defines the HTTP boundary. No YAML or prompt language
is required from customers. No LLM runs in the execution path.

Your backend creates a short-lived session from its authenticated user and
account. The browser renders `<AutomationCreator client={client} owner={owner}/>`.
The supplied owner adapter uses the connected wallet and OAAth's durable
Operation journal. The application API credential never reaches the browser.

The application configures `keyScope: "user"` (default) or `"application"`.
The latter shares one onchain session signing key across that application's
users. Each automation still has separate consent, a Grant, an executor,
schedule and operation history. Scope is frozen in the plan and signed consent;
changing the setting affects new plans only. Cancellation revokes that plan's
authority without deleting its shared key.

## Ownership

| Location / dependency | Owns |
| --- | --- |
| `api/` (Rust, Axum, SQLx) | Authentication, sessions, plan lifecycle, due-slot scheduling, retained projections |
| `sdk/` (TypeScript) | HTTP client; `/server`, `/react`, `/wallet`, `/approval`, `/journal`, `/cancellation` subpaths |
| `runtime/` (private TypeScript worker) | OAAth composition, signing admission, execution and cancellation reconciliation |
| `protocol/dca.ts`, `api/src/recipes/dca.rs` | Matching canonical DCA codec and schedule semantics |
| `recipes/dca/contracts/` | Per-plan spending, price, recipient, timing and cancellation enforcement |
| `examples/dca/` | Consumer of the public SDK; local test-owner fixture integration |
| OAAth | Authority, scoped signer registry, Grants, caller-keyed publication, Operation identity and finality |
| Cetane | Ethereum codecs, hashes, signatures and transport primitives |
| Moesi | Pinned deployment verification through its Cetane observer |

The private worker belongs to the API deployment, not a third public product.
There is one Operation state machine and no additional nonce allocator. Runtime
code and packed OAAth production dependencies do not use viem; fixture and parity
tests may use it as an independent oracle. Cetane 0.0.3 and Moesi 0.15.3 are installed from npm; OAAth uses exact local
tarballs. Archives, hashes, registry integrity and source commits are retained
in `vendor/` and `vendor/provenance.json`.

This is unreleased: the repository has one current schema and API, with no
compatibility or data-migration layer. Unsupported recipes fail closed. Adding
a recipe requires its own codec, enforcement and proof; arbitrary calldata,
workflow graphs, chains, tokens and routes are not accepted.

## Run the local product

Requires Bun, Rust via rustup, Foundry/Anvil, PostgreSQL CLI tools and Tailscale.

```sh
bun install --frozen-lockfile
bun dev
```

Startup builds the product, uses owned Anvil and PostgreSQL fixtures, discovers
Tailscale identity and verifies the private preview. Browser example: loopback
4320 forwarded through Tailscale TCP. Rust API: 4317, also forwarded. The private
worker (4318), owner fixture (4319) and database (55437) stay on loopback.
Unrelated Tailscale Serve mappings are preserved. The example serves an explicit
three-file allowlist; it never serves the repository or private configuration.

The example uses a clearly labelled local test owner and test funds. Its owner
bridge only signs the requesting user's retained plan review and exact setup /
cancellation calls. It is fixture infrastructure, not a production wallet or
customer identity provider. Use `/wallet` and your own authenticated backend
session endpoint when embedding the product.

`.local/environment.json` contains generated local credentials and the sealing
key (0600, ignored by Git). PostgreSQL and the sealing key must survive restarts
together. Recreate services with `bun scripts/run.mjs api`, `runtime`, or `web`;
set `AUTOMATION_RELEASE=1` to use the release API. Missing custody fails closed.

## Proof and limits

[Implementation and proof record](IMPLEMENTATION_PLAN.md) tracks the current
boundary. [Evidence](evidence/automation-product.md) records exact local checks.
The complete proof uses real Kernel v4 / EntryPoint 0.9, real Uniswap v3, separate
PostgreSQL connections, process death and exact packed consumers. A finalized
purchase requires matching executor event and Operation evidence.

Worker budgets count RPC methods, reuse bounded ports, and defer exhausted work
to an explicit window. Moesi shares the admission budget. Unresolved operations
block new work for that plan and use bounded observation backoff. Status/history
read retained projections; dashboard polling never polls the chain.

No public-chain deployment, package publication, sponsorship, production custody
service, independent security audit or live-provider performance claim is made.
