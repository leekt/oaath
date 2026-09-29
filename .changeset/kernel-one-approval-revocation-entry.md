---
"@oaath/sdk": minor
"@oaath/server": patch
---

Breaking: `@oaath/sdk/kernel` exports no `Phone` names. Where the owner key
lives is expressed by who signs, not by the function name.

- `prepareKernelPhonePermissionApproval` becomes `prepareKernelPermissionApproval`.
  Its preparation gains `sign(ownerKey, decidedAt)`, which takes the one owner
  signature from a key profile. `complete(artifact, decidedAt)` still accepts
  an owner device's signing artifact. `KernelPhonePermissionArtifact` becomes
  `KernelPermissionDecision`. A request this preparation does not support (a
  Kernel `0.3.3` or existing account, or a non-P-256 owner) now fails with
  `kernel_runtime_unsupported` before any signing.
- `prepareKernelPhoneRevocation` and `restoreKernelPhoneRevocation` are
  deleted. `prepareKernelPermissionRevocation` now prepares a Kernel `0.4.0`
  owner revocation when given the optional `request` and `effect` settings,
  instead of failing with `kernel_runtime_unsupported`.
  `restoreKernelPermissionRevocation({ preparation })` accepts that
  revocation's `signingRequest`, and `reads` is required only for a recorded
  Kernel `0.3.3` preparation. Every preparation offers `sign(ownerKey)`; the
  Kernel `0.4.0` kind also offers `complete(artifact)` for an owner device.
- The `@oaath/server/kernel` revocation executor restores through
  `restoreKernelPermissionRevocation`.

No wire or persisted artifact version changes.
