---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Add version-agnostic Kernel account entry points to `@oaath/sdk/kernel`.
Kernel version and EntryPoint version are optional settings.

- `kernelDeployment({ chainId, kernelVersion?, entryPoint? })` selects a
  deployment and defaults to Kernel `0.4.0` on EntryPoint `0.7`.
- `createKernelReads(publicClient)` is one read capability for every supported
  deployment.
- `bindKernelAccount({ chainId, reads, address })` detects an existing
  account's deployment from its onchain implementation. That includes
  deployed Kernel `0.4.0` accounts, bound by address. Pass `initialPackages`
  and `accountIndex` instead to derive a Kernel `0.4.0` account.
  `kernelAccountDeployment(account)` returns the detected deployment.
- `prepareKernelUserOperation` prepares for any bound account.
- `createKernelRuntime` accepts any `KernelDeployment`, and
  `runtime.bindAccount({ address })` binds an existing account of that
  deployment.

An explicit `deployment` that disagrees with the account fails with
`kernel_runtime_deployment_mismatch` before any signing. It never switches
versions.

Owner mode is no longer Kernel `0.3.3`-only: `review.kernelVersion` reports
the detected version. The owner operation lane label no longer includes a
version, so owner operations saved by an earlier release are not recovered.

Breaking: `bindKernelAccount` no longer takes `version`.
`@oaath/testing`'s owner fixture accepts `kernelVersion`.
