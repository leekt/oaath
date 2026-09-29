---
"@oaath/sdk": minor
---

Add `prepareKernelPermissionRevocation` and `restoreKernelPermissionRevocation`
to `@oaath/sdk/kernel`. They split an owner revocation of one Grant approval
into separate awaited stages that do not depend on the transport. Preparation
only reads. It returns a JSON-safe, versioned
(`oaath.kernel-permission-revocation/v1`) record: approval, root owner,
permission state, canonical teardown calls, lane, gas, and the exact unsigned
prepared operation with its hash. `sign(owner)` produces one owner signature over
exactly that operation and never submits. The caller routes the operation and
signature itself, then observes with `verifyKernelPermissionRevocation`.

Restoring a record re-derives the calls and operation on the same account. A
changed approval, state, lane, gas, or hash is rejected before signing, as are
another owner key and a contradicting `account`, `kernelVersion`, or
`entryPoint`. Only Kernel v3.3 approvals are implemented. A v4 approval fails
with the new `kernel_runtime_unsupported` code, and v4 owner revocation remains
`prepareKernelPhoneRevocation`.
