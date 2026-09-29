---
"@oaath/sdk": minor
---

Add `verifyKernelPermissionApproval({ approval, expected })`, a pure offline
check of a permission approval against the reviewed owner, account, permission
ID, session key and ordered packages. It dispatches on `approval.version`; only
Kernel v3.3 approvals with an EOA root owner verify today, and other approval
kinds return an `unsupported` version mismatch. A well-formed but wrong approval
returns a typed `{ status: "mismatch", field, reason }`. It makes no RPC call and
implies nothing about chain readiness or installation.
