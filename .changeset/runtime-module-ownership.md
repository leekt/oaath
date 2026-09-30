---
"@oaath/sdk": patch
"@oaath/cli": patch
---

Mark ZeroDev CallPolicy, operation-limit policy, ECDSA signer and Daimo P-256 verifier as externally deployed. `prepareRuntimeModuleDeployment` returns null for these modules. The CLI requires their pinned runtimes before deploying OAAth-owned modules.
