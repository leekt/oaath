---
"@oaath/sdk": patch
---

`createOAAth({ chains, approvals: { kind: "oauth", issuer, clientId, redirectUri } })`
requests Grants through the OAAth portal popup. The SDK names its own
non-extractable session key as the Grant signer, accepts only a returned
permission request that is exactly its own (signer, application, policy,
expiry), and applies the account root's replayable install through the existing
local approval path, so the first `sendCalls` installs the permission.
