---
"@oaath/sdk": minor
---

`prepareKernelPermissionApproval` prepares and signs a request for an existing
Kernel `0.3.3` or `0.4.0` account whose ECDSA or raw P-256 root owner is proven
onchain, through the same owner wallet-approved mode uses.

- `reads` is `KernelReads` (`createKernelReads`), which serves every supported
  deployment.
- `signingRequest` is typed as the generic `kernel-enable`
  `Eip712OwnerSigningRequest`; a Kernel `0.4.0` request is still the replayable
  install request.
- `KernelPermissionDecision.installApproval` may be a Kernel `0.3.3` approval;
  branch on its `version`.
- `complete(artifact)` fails with `kernel_runtime_unsupported` unless the owner
  is P-256.
- Wallet-approved chains that need different approvals now fail with source
  `kernel_runtime_binding_mismatch` instead of `local_permission_scope_mismatch`
  (still `oaath_client_state_conflict`).
