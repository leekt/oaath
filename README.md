# OAAth

OAAth is OAuth for scoped smart-account authority. It is an OAuth 2.0 and
OpenID Connect issuer for Kernel v4 smart accounts, hosted at
<https://oaath.taek.tech>. A dapp signs users in with their smart account
("Login with OAAth"), asks for a scoped, expiring Grant for its own session key,
or asks the account's root to sign one exact operation. The account root
reviews and signs in the OAAth portal. The SDK then executes the Grant through
the dapp's own bundler and never resubmits an operation it cannot observe.

## Architecture

| Path | What it is |
| --- | --- |
| [`relay/`](relay) | `oaath-relay`, the Rust issuer: OAuth/OIDC endpoints, the portal API, signers, accounts and memberships, Grant composition and verification. Memory or PostgreSQL store. |
| [`portal/`](portal) | The portal SPA (React) and its Cloudflare Worker at `oaath.taek.tech`. The Worker serves the SPA, forwards `/oauth/*` and `/portal/*` to the relay, and budgets chain reads. |
| [`packages/`](packages) | The TypeScript packages below. |
| [`examples/`](examples) | Runnable examples. |

The relay holds no account keys. A Grant's authority is the account root's own
Kernel replayable-install signature, which Kernel verifies on chain; an owner
operation is the root's signature over one exact UserOperation hash. The relay
verifies both before releasing them, and the SDK verifies them again.

## Login with OAAth

The portal is signer-first. A user signs in with a **signer**: a wallet, proven
with Sign-In with Ethereum (`personal_sign`), or a passkey, proven with a
WebAuthn assertion. A signer then acts on **accounts**:

- **create**: a new factory-derived Kernel v4 account whose root is the signer;
  it stays counterfactual until its first operation deploys it;
- **import**: an existing Kernel account, after the relay proves the signer is
  its root on chain (read-only, budgeted RPC);
- **link**: a new signer asks to join an existing account and the root approves
  it, sign-in only or with a policy template, so the root's one signature is
  also the member's Grant;
- **templates**: the root's named, reusable Grant policies;
- **suspend, restore, remove**: the root manages its members; a suspended
  member cannot sign in as the account.

A member's Grant request waits for the account root, who approves or rejects
it from the account's pending requests in the portal.

## Dapp API

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery. |
| `GET /oauth/jwks` | The ES256 id_token keys. |
| `POST /oauth/clients` | Open registration of a public client (`client_name`, `redirect_uris`). |
| `POST /oauth/par` | Pushed authorization request: PKCE S256, `scope=openid`, and optionally one `authorization_details` entry, `oaath_grant` (signer, policy, chains, expiry, device) or `oaath_operation` (one exact owner-operation request). |
| `GET /authorize?client_id&request_uri` | The portal page where the user chooses a signer and account, and the root reviews. |
| `POST /oauth/token` | The code exchange. The id_token carries `sub` (the account), `oaath_account`, `oaath_accounts`, `signer` and `verified`; `authorization_details` carries the approved Grant or the signed operation. A member's Grant answers `400 authorization_pending` until the root decides, then the Grant or `access_denied`. |
| `POST /oauth/revoke` | RFC 7009 revocation of the client's own access token. |
| `GET /oauth/grants/{id}`, `POST /oauth/grants/{id}/invalidate` | A Grant's view, with its bearer token, and its off-chain capability invalidation, with the bearer token or a proof signed by the Grant's own operator key. |

The [relay README](relay/README.md) lists the portal API.

## SDK

```sh
npm install @oaath/sdk
```

| Call | Use |
| --- | --- |
| `loginWithOAAth({ issuer, clientId, redirectUri })` | Sign in; resolves to the account, signer, every active membership, and the verified id_token. |
| `createOAAth({ chains, approvals: { kind: "oauth", issuer, clientId, redirectUri } })` | Portal-approved Grants for the SDK's own session key. `requestPermission` returns a Grant, or `{ state: "pending" }` for a member's request; `redeemPending()` redeems it once the root approves. |
| `createOAAth({ chains, account, approvals: { kind: "wallet", owner } })` | Grants approved by a connected wallet for an existing account; no portal. |
| `createOAAth({ chains, account })` | Owner-only execution from an existing Kernel account. |
| `requestOwnerOperationApproval({ issuer, clientId, redirectUri, request })` | The root signs one exact owner operation in the portal; the SDK verifies it for the dapp's own submission. |

```ts
import { createOAAth } from "@oaath/sdk";

const oaath = createOAAth({
  chains: { 421614: { publicRpcUrls: [rpcUrl], bundlerUrl } },
  approvals: { kind: "oauth", issuer: "https://oaath.taek.tech", clientId, redirectUri },
});
const connection = await oaath.connect();
const grant =
  (await connection.resume()) ??
  (await connection.requestPermission({
    chainScope: "all",
    permissions: [{ calls: [{ target, selectors, valueLimit: "0" }] }],
    expiresIn: 1800,
    perChainOperationLimit: 10,
  }));
if (grant.state === "pending") {
  // A member's request: call connection.redeemPending() later.
} else {
  const operation = await grant.sendCalls({ chain: 421614, calls });
  await operation.wait();
}
```

A Grant is one all-chain owner approval: its first operation on a chain
deploys the account if needed and installs the permission in enable mode. Every
operation's identity, submission evidence and observation stay chain-local and
survive a reload. The [SDK README](packages/sdk/README.md) covers the realms,
the Kernel runtime, chain ports and the wallet RPC standards.

## Packages

| Package | Purpose |
| --- | --- |
| `@oaath/protocol` | IO-free wire and durable contracts: permission requests and decisions, Grants, operations, owner operations, identity profiles. |
| `@oaath/sdk` | Browser client plus the concrete Kernel/ZeroDev runtime. |
| `@oaath/testing` | Deterministic fixtures and local Anvil harnesses; never a production dependency. |
| `@oaath/cli` (`oaath`) | Runtime readiness checks and deterministic deployment of the pinned contracts. |

All four are one fixed `0.x.y` release group; no package becomes `1.0.0` during
this program. Versioned source does not imply npm publication.

## Examples

| Example | Shows |
| --- | --- |
| [`examples/oauth-login`](examples/oauth-login) | Login with OAAth from a static page. |
| [`examples/oauth-grant-demo`](examples/oauth-grant-demo) | A portal-approved Grant, including a member's pending request, then one covered call that deploys and enables (live Arbitrum Sepolia, opt-in). |
| [`examples/extension`](examples/extension) | An MV3 wallet extension announcing an EIP-6963 Grant provider; pairing runs through `chrome.identity.launchWebAuthFlow`. |
| [`examples/all-chain`](examples/all-chain) | One owner approval materialized on a chain introduced afterwards. |

## Development

Requirements: Node.js 22.13 or newer, Bun 1.4.2 (pinned in `package.json`),
Rust for `relay/`, and Foundry's Anvil for local chain tests.

```sh
bun install
bun run typecheck
bun run test
bun run lint
bun run fixtures:protocol                 # regenerate the relay's protocol fixtures
bun run --filter @oaath/sdk test:anvil
bun run --filter @oaath/portal test:e2e   # relay binary, portal Worker, headless Chrome
```

Automated tests never contact paid or shared RPC services; they use local Anvil
and loopback servers. Repository rules live in [AGENTS.md](AGENTS.md).

Packaging gates prove the published artifacts, not the workspace:
`check:public-surface`, `smoke:protocol`, `smoke:cetane`, `smoke:extension`
(the packed extension in headful Chrome against the relay binary, with a forced
MV3 worker restart and no resubmission) and `smoke:all-chain`.

## Release

The fixed group publishes together; publishing is a manual, owner-authorized
action and no workflow runs it.

```sh
bun run changeset         # describe the change
bun run release:status    # what would be released
bun run release:version   # apply versions and changelogs
bun run release:check     # pack every public package; no publishing or tags
bun run release:publish   # owner only: publish the fixed group and tag it
```

Publish only from `main` after the versioning PR has merged. Existing published
versions are tolerated so a partial release can be resumed; tags are created
only after every package succeeds.

## License

Apache-2.0, including the OAAth-owned validity policy source and its embedded
SDK/CLI bytecode. The policy declares the
[CC0 ERC-4337 packed ABI](https://eips.ethereum.org/EIPS/eip-4337#entrypoint-interface)
locally and imports no GPL implementation. Third-party contracts and their
artifacts retain their upstream licenses.
