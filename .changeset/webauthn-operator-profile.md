---
"@oaath/sdk": patch
---

`kernelKey` WebAuthn signing input accepts the operator credential profile
(`oaath.operator-credential-profile/v1`) as well as the owner profile, as the
public `credential` input already does. The profile's role does not change the
key's public material or signing.
