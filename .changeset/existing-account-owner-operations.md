---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Owner operations accept an existing (imported) Kernel 0.4.0 account: `prepareOwnerOperation` sends from the profile's own address with no factory (the account is deployed), and `verifyOwnerOperation` binds the sender to that address and the EntryPoint to 0.9. A Kernel 0.3.3 profile, or a factory on an existing account, is refused.
