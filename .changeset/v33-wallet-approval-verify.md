---
"@oaath/sdk": patch
---

`verifyKernelPermissionApproval` accepts a Kernel v3.3 enable signature over
the EIP-191 hash of the digest, which is what `kernelKey({ wallet })`
produces with `personal_sign`, as well as the raw-digest `signTypedData`
form. These are the two forms Kernel v3.3's ECDSA validator accepts, so the
offline check agrees with the chain.
