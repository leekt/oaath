---
"@oaath/sdk": minor
"@oaath/testing": patch
---

`createOAAth` takes one options shape for owner and wallet-approved execution;
the approval source is the optional `approvals` setting. `mode` is removed with
no alias.

- `createOAAth({ mode: "owner", chains, operations })` is now
  `createOAAth({ chains, account?, stores?: { operations } })`. With `account`
  set, `oaath.account(address)` refuses every other address.
- `createOAAth({ mode: "local", owner, onApproval, account, chains, ... })` is
  now `createOAAth({ chains, account, approvals: { kind: "wallet", owner, onApproval? }, ... })`.
- The result type follows the options: without `approvals` it is
  `OaathOwnerClient`; wallet approvals return `OaathWalletApprovalClient`.
- Renamed types: `OaathLocalConfiguration` and `OaathOwnerConfiguration` become
  `OaathWalletOptions` and `OaathOwnerOptions`; `OaathLocalClient`,
  `OaathLocalWallet` and `OaathLocalApprovalReview` become
  `OaathWalletApprovalClient`, `OaathApprovalWallet` and
  `OaathWalletApprovalReview`.
