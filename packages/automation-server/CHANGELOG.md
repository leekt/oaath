# @oaath/automation-server

## 0.3.11

### Patch Changes

- 8d14cca: On-demand automations: a definition of `kind: "on-demand"` names chains, an exact call list (target, selector, value limit) and a per-chain operation limit, with no schedule. One plan's Grant covers every listed chain; the application then submits exact calls with `POST /v1/plans/{id}/operations`, each admitted only when it fits the approved policy, persisted on a `request` run and sent exactly once. Runs carry their chain, and `GET /v1/plans/{id}/runs/{runId}` reads one back. The PostgreSQL schema is now `oaath.automation-postgres-schema/v3`: drop and recreate the database.
- Updated dependencies [8d14cca]
- Updated dependencies [6de424a]
- Updated dependencies [814e39c]
  - @oaath/automation@0.3.11
  - @oaath/protocol@0.3.11
  - @oaath/sdk@0.3.11

## 0.3.10

### Patch Changes

- Updated dependencies [1455629]
- Updated dependencies [c1f2f2d]
  - @oaath/protocol@0.3.10
  - @oaath/sdk@0.3.10
  - @oaath/automation@0.3.10

## 0.3.9

### Patch Changes

- Updated dependencies [ba0c172]
- Updated dependencies [1f7f317]
- Updated dependencies [87f62f5]
  - @oaath/protocol@0.3.9
  - @oaath/sdk@0.3.9
  - @oaath/automation@0.3.9

## 0.3.8

### Patch Changes

- Updated dependencies [f3abb35]
  - @oaath/protocol@0.3.8
  - @oaath/automation@0.3.8
  - @oaath/sdk@0.3.8

## 0.3.7

### Patch Changes

- Updated dependencies [6fdac81]
- Updated dependencies [d6c76fc]
- Updated dependencies [7df2252]
  - @oaath/sdk@0.3.7
  - @oaath/protocol@0.3.7
  - @oaath/automation@0.3.7

## 0.3.6

### Patch Changes

- ddae33b: Add optional `AUTOMATION_BUNDLER_API_KEY_<chainId>`: when set, the executor sends it to that chain's bundler only, as the JSON-RPC `apiKey` field (bundle_rs client authentication).
- 1abef87: The service sends its plan's user and account as the issuer's `login_hint` (`<signer_id>@<account>`), so the OAAth portal opens on the review with no signer or account picker. A session's `userId` is the user's OAAth signer id.
- 16851cd: Add optional `AUTOMATION_PAYMASTER_API_KEY_<chainId>`: when set, the executor sends `{ apiKey }` as the ERC-7677 paymaster context (as paymaster-rs accepts it) instead of `{}`.
- ee46925: Add optional `AUTOMATION_RELAY_PAYS_GAS_<chainId>=true`: the chain's bundler pays gas (bundle_rs fast mode), so operations carry zero fees and use no paymaster. It is refused together with a paymaster URL.
- 70d17bd: Activate an automation plan once its setup operation is included and successful, rather than finalized, so occurrences are no longer held for L1 finality. With a setup, occurrence slot N now runs on nonce lane N + 1, leaving lane 0 to the setup while it awaits finality. An authorized plan waits for its setup until its Grant ends and then expires with `setup_not_included`; a setup that fails, reverts or drops fails the plan even after activation; slots opening after the approved Grant's end are skipped as `grant_expired`. The schema is unchanged.
- 4ca33aa: Run each automation occurrence on its own Kernel nonce lane, so a due slot no longer waits for the previous slot's finality. At most `AUTOMATION_MAX_OPEN_SLOTS` (default 4) occurrences of one plan are open at once. The automation schema is now `oaath.automation-postgres-schema/v2`; drop and recreate the automation database. An explicit SDK operation lane may now start once the Grant's installing operation is included, rather than finalized, and runs in standard mode.
- 1899cf5: Add declarative automations. `@oaath/automation` owns the definition schema, plan terms, the derived Grant policy and the service client; `@oaath/automation-server` is a self-hostable service (HTTP API, scheduler and executor over PostgreSQL) that obtains Grants as an OAuth client of an OAAth issuer and executes each occurrence at most once.
- Updated dependencies [1abef87]
- Updated dependencies [4ca33aa]
- Updated dependencies [4187af9]
- Updated dependencies [05148ef]
- Updated dependencies [1899cf5]
- Updated dependencies [4a3ad72]
- Updated dependencies [0dce3ad]
- Updated dependencies [8aacee9]
- Updated dependencies [e0a4255]
- Updated dependencies [ee46925]
- Updated dependencies
- Updated dependencies [ddae33b]
- Updated dependencies [f946694]
  - @oaath/automation@0.3.6
  - @oaath/sdk@0.3.6
  - @oaath/protocol@0.3.6
