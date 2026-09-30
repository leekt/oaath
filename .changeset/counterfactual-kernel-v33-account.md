---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/server": patch
"@oaath/testing": patch
"@oaath/cli": patch
---

Kernel `0.3.3` ECDSA-owned accounts can be derived and activated without
ZeroDev's SDK. `deriveKernelAccount({ deployment, owner, accountIndex })`
returns the account address and the EntryPoint 0.7 `factory` / `factoryData`
of ZeroDev's MetaFactory route, byte for byte what ZeroDev's
`createKernelAccount` derives. `bindKernelAccount({ chainId, reads, deployment,
owner, accountIndex })` and an owner runtime's `bindAccount({ accountIndex })`
bind that account: a deployed one exactly as an existing account, a
counterfactual one only after the pinned factory and MetaFactory code and the
factory approval are proven. Its first prepared operation carries the
MetaFactory deployment.
