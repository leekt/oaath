---
"@oaath/sdk": patch
"@oaath/testing": patch
---

Remove the phone-approved service realm (`approvals: { kind: "service" }`) and the relay authorization client: the injected `issuer` and `authorization` ports, pending-authorization recovery (`resumePendingPermission`, `withdrawPendingPermission`, `onPending`, and the context store's `compareAndSwapPending`), and remote phone revocation custody (`ownerRevocations`). The injected composition now takes `approve(request)`, the owner's decision for exactly the reviewed request. `@oaath/testing` local fixtures approve in-process and drop `openServiceClient`.
