# @oaath/automation

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
