---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Sudo grants: a GrantPolicy with `calls: []` lets the session key make any call the account can, and is accepted only with a non-null `validUntil` whose inclusive window spans at most `OAATH_SUDO_GRANT_MAX_SECONDS` (600) seconds (`validUntil - validAfter + 1 <= 600`) and `perChainOperationLimit: null`. It installs a Kernel permission whose only policy is the validity policy. `isSudoGrantPolicy` identifies one; coverage permits every call, and only a sudo request may be approved as sudo. An app requests one with `permissions: [{ calls: [] }]`, `expiresIn` of at most 600 and `perChainOperationLimit: null` (now also accepted for any unlimited request). Policy templates are never sudo, and the OAAth portal warns that the app gets full control of the account before the root signs.
