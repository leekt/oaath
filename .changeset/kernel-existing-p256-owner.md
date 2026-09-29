---
"@oaath/sdk": minor
---

`runtime.bindAccount({ address })` proves a raw P-256 root owner on an existing
Kernel 0.4.0 account. It reads the public key stored in the pinned P-256
validator and compares it with the key's public material. Any other root
validator, including WebAuthn, still fails with `kernel_runtime_binding_mismatch`.
