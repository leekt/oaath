---
"@oaath/sdk": patch
---

`@oaath/sdk/kernel` exports `signedKernelPermissionApproval({ runtime, account,
nonce, owner, typedData, signature })`. It assembles a Kernel permission
approval from an enable typed-data signature taken elsewhere, such as a browser
wallet's `eth_signTypedData_v4`. The typed data must hash to the permission's
enable digest (`kernel_runtime_binding_mismatch`), and the signature must
recover to the owner (`kernel_runtime_signature_invalid`). The approval entry
points also accept a Kernel 0.3.3 runtime without a cast.
