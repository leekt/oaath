---
"@oaath/sdk": patch
---

`@oaath/sdk/kernel`'s `KernelDeployment`, `KernelRuntime` and
`CreateKernelRuntimeInput` take an optional Kernel version argument, selected
by the deployment's own `kernelVersion` discriminant. For example,
`KernelRuntime<"0.3.3">` names the Kernel 0.3.3 runtime, with its v3.3
deployment fields, account descriptor and `enable` mode, and needs no cast.
With no argument, each type still covers either version. No export name
carries a version.
