---
"@oaath/sdk": minor
---

Add ecdsaWalletKey for a connected viem wallet. It requests one EIP-191 signature
over the exact operation digest and verifies the captured owner locally before
returning the existing Kernel ECDSA envelope. Wallet rejection is never retried.
