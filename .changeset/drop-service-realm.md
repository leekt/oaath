---
"@oaath/sdk": patch
"@oaath/testing": patch
---

Remove the phone-approved service realm (`approvals: { kind: "service" }`) and the relay authorization client with its injected `issuer` and `authorization` ports. The injected composition now takes `approve(request)`, the owner's decision for exactly the reviewed request. `@oaath/testing` local fixtures approve in-process and drop `openServiceClient`.
