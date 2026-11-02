# @oaath/automation

## 0.3.11

### Patch Changes

- 8d14cca: On-demand automations: a definition of `kind: "on-demand"` names chains, an exact call list (target, selector, value limit) and a per-chain operation limit, with no schedule. One plan's Grant covers every listed chain; the application then submits exact calls with `POST /v1/plans/{id}/operations`, each admitted only when it fits the approved policy, persisted on a `request` run and sent exactly once. Runs carry their chain, and `GET /v1/plans/{id}/runs/{runId}` reads one back. The PostgreSQL schema is now `oaath.automation-postgres-schema/v3`: drop and recreate the database.
- Updated dependencies [6de424a]
- Updated dependencies [814e39c]
  - @oaath/protocol@0.3.11

## 0.3.10

### Patch Changes

- Updated dependencies [1455629]
- Updated dependencies [c1f2f2d]
  - @oaath/protocol@0.3.10

## 0.3.9

### Patch Changes

- Updated dependencies [ba0c172]
- Updated dependencies [87f62f5]
  - @oaath/protocol@0.3.9

## 0.3.8

### Patch Changes

- Updated dependencies [f3abb35]
  - @oaath/protocol@0.3.8

## 0.3.7

### Patch Changes

- @oaath/protocol@0.3.7

## 0.3.6

### Patch Changes

- 1abef87: The service sends its plan's user and account as the issuer's `login_hint` (`<signer_id>@<account>`), so the OAAth portal opens on the review with no signer or account picker. A session's `userId` is the user's OAAth signer id.
- 1899cf5: Add declarative automations. `@oaath/automation` owns the definition schema, plan terms, the derived Grant policy and the service client; `@oaath/automation-server` is a self-hostable service (HTTP API, scheduler and executor over PostgreSQL) that obtains Grants as an OAuth client of an OAAth issuer and executes each occurrence at most once.
- 8aacee9: Accept a bundler's `paymasterPostOpGasLimit` estimate in ERC-7677 sponsorship (validated, never replacing the paymaster's own post-op limit), and make the automation client refuse redirects with `redirect: "manual"` so it works inside Cloudflare Workers.
- Updated dependencies [f946694]
  - @oaath/protocol@0.3.6
