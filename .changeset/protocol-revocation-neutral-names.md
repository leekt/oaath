---
"@oaath/protocol": minor
"@oaath/sdk": patch
"@oaath/server": patch
---

Breaking: the `@oaath/protocol` Kernel revocation exports no longer name a
Kernel version. The signing request's own `version` discriminant
(`oaath.kernel-revocation-signing-request/v1`, unchanged) carries the version.

- `OAATH_KERNEL_REVOCATION_SIGNING_REQUEST_VERSION` replaces
  `OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION`.
- `parseKernelRevocationSigningRequest` and `hashKernelRevocationSigningRequest`
  replace their `KernelV4` forms.
- `encodeKernelInstallNonceInvalidationCall` and
  `encodeKernelPermissionUninstallCalls` replace their `KernelV4` forms.
- The types `KernelRevocationEffect`, `KernelRevocationOperation` and
  `KernelRevocationSigningRequest` replace their `KernelV4` forms.
