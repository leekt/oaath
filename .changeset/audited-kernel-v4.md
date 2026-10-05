---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/server": patch
"@oaath/testing": patch
"@oaath/cli": patch
---

Pin Kernel v4 to upstream PR #152 at c960b42d2ed4adb0d5328f6e762962debdf8e57a,
with reproducible runtime artifacts and new CREATE2 addresses bound to EntryPoint
0.7. Update validator and signer install data for the scoped-hook contract:
remove the inline hook argument, reject module type 4, and accept type 11 in the
shared and native approval parsers. Remove per-chain implementation hash pins;
all chains use canonical CREATE2 code presence and exact factory/account
implementation bindings. Chain-independent factory and module hashes remain checked.

Prior v4 deployments and grants require fresh setup. The existing Kernel 0.3.3
profile remains supported. No public deployment or OAAth audit is claimed.
