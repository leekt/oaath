---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Owner transactions may carry optional EIP-3085 `chain` metadata (`name`, `nativeCurrency` with 18 decimals, one to four canonical `https` `rpcUrls`, optional `blockExplorerUrls`; no credentials, query or fragment), bound by `hashOwnerTransactionRequest`. When the root's wallet does not know the chain (4902), the OAAth portal adds it from that metadata, switches, then sends; without it, the portal still refuses.
