---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Owner operations support an existing, deployed Kernel 0.3.3 account: `prepareOwnerOperation`, `verifyOwnerOperation` and the `oaath_operation` portal approval sign and verify its EntryPoint 0.7 UserOperation hash (a raw or EIP-191 ECDSA root signature). `ownerOperationEntryPointVersion` names an account's EntryPoint version. A Kernel 0.3.3 owner operation carries no factory.
