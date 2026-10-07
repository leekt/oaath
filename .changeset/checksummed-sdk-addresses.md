---
"@oaath/sdk": patch
---

Normalize single-case and EIP-55 account, call, module, routing and paymaster inputs through the shared protocol owner. Reject invalid mixed-case checksums before signing, with field diagnostics, while preserving operation and capability hashes.
