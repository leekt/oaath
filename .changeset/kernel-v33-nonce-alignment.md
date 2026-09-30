---
"@oaath/sdk": patch
---

`@oaath/sdk/kernel` exports `kernelPermissionNonceAlignmentCalls({ runtime,
account, reads, nonce })`. It returns the owner calls that raise one chain's
Kernel 0.3.3 enable nonce for a not-yet-installed permission to a target, so
one approval covers chains whose nonces differed. The calls install and remove
a throwaway permission that never validates. They never raise
`validNonceFrom`, so installed permissions keep working.
