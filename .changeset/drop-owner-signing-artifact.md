---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Remove the owner-device signing artifact and the Kernel 0.4.0 revocation signing request. Approvals complete only through `sign(ownerKey, decidedAt)`; `prepareKernelPermissionRevocation` is Kernel 0.3.3 only, and a Kernel 0.4.0 Grant revokes through its grant handle.
