---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/testing": patch
---

The owner key is an optional setting in owner and wallet-approved modes.

- `account(address).owner(owner)` and `approvals: { kind: "wallet", owner }`
  take a connected viem wallet (the ECDSA default, unchanged) or any
  `kernelKey(...)` signing profile, such as a raw P-256 key. A wallet approves a
  Grant with one typed-data prompt; a key profile signs the same approval digest.
  New types: `OaathOwnerKey` and `OaathApprovalOwner`.
- The existing-account profile is `oaath.kernel-existing-account-profile/v3`. It
  admits an ECDSA owner, or a raw P-256 owner on Kernel `0.4.0`. The `v2`
  profile has no reader; recreate stored bindings and Grants.
- A WebAuthn owner key fails with `oaath_client_capability_unsupported`
  (`source: "owner_key_kind_unsupported"`) before it signs, because no WebAuthn
  root validator is pinned.
- `createLocalOwnerAnvilFixture({ kernelVersion: "0.4.0", owner: "p256" })`
  roots the fixture account in a raw P-256 `ownerKey`.
