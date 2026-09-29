---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": patch
---

Breaking: `@oaath/sdk/kernel` no longer exports the version-named deployment,
read, bind and prepare entry points or their types. Use the generic entry
points instead:

- `kernelDeployment({ chainId, kernelVersion? })` replaces
  `kernelV4Deployment` and `kernelV33Deployment`.
- `createKernelReads` replaces `createKernelV4Reads` and
  `createKernelV33Reads`.
- `bindKernelAccount` replaces `bindKernelV4Account`.
- `prepareKernelUserOperation` replaces `prepareKernelV4UserOperation`.
- `KernelDeployment`, `KernelReads`, `KernelReadRequest`, `KernelReadClient`
  and `KernelAccountDescriptor` replace the version-named types.

`createKernelRuntime` returns one `KernelRuntime` type for every deployment.
