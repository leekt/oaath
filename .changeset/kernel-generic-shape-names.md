---
"@oaath/protocol": minor
"@oaath/sdk": patch
---

Breaking: `@oaath/protocol` renames `KernelV4Install` to `KernelInstall`. The
SDK's shared Kernel shapes (`KernelCall`, `KernelInstall`,
`KernelUserOperationGas`, `KernelValidation`, `KernelValidityTimeRange`) are
now the owner types themselves instead of aliases of version-named shapes.
