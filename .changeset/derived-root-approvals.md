---
"@oaath/sdk": patch
---

Prepare and sign Kernel permission approvals for factory-derived Kernel 0.4.0 accounts whose single root is an ECDSA (through `ECDSA_VALIDATOR`) or WebAuthn owner, as well as P-256. A non-factory route still fails with `kernel_runtime_unsupported` before signing.
