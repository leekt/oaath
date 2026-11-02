---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Owner transactions: `requestOwnerTransaction` asks the signer whose wallet is `from` to review and send one exact plain transaction (value-bearing calls and contract creations) in the OAAth portal, returning the wallet's hash; `hashOwnerTransactionRequest` is its identity before sending. `portalWallet` serves the connected-EOA wallet shape for `payer`, so the EntryPoint-direct fallback and plain sends go through the portal.
