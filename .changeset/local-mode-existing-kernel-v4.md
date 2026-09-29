---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": patch
---

Breaking: the existing-account profile is now
`oaath.kernel-existing-account-profile/v2`. It admits any supported deployment,
with a `kernelVersion` of `"0.3.3"` or `"0.4.0"` detected from the account. `v1`
profiles are rejected and must be recreated. `KernelV33AccountProfile` becomes
`KernelExistingAccountProfile`, and `isKernelExistingAccountProfile` tells it
apart from a derived profile.

Local mode now accepts an existing Kernel v4 account. It detects the
account's deployment on every configured chain, and chains that disagree fail
with `local_account_deployment_mismatch`. The wallet approval uses the selected
deployment's approval artifact.
