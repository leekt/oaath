---
"@oaath/sdk": patch
---

`portalOwnerKey({ issuer, clientId, redirectUri, account })`: an owner key for `createOAAth(...).account(address).owner(key)` whose every `sendCalls` signature comes from the account's root in the OAAth portal, over the realm's own prepared operation; routing, the connected-EOA fallback and journaling are unchanged. Pass `launch` because sends run outside the user's gesture.
