---
"@oaath/sdk": patch
"@oaath/cli": patch
---

`@oaath/sdk/kernel` exports `kernelRuntimeReadiness({ chainId, reads })`,
which reports each OAAth runtime module (WebAuthn signer, RateLimit policy,
validity policy, P-256 verifier) as `present`, `missing`, `mismatch` (other
code occupies the address, so deploying cannot fix it) or `unreadable`, and
`prepareRuntimeModuleDeployment({ chainId, module })`, which returns the exact
CREATE2 deployer transaction `{ module, address, to, data, value,
expectedRuntimeCodeHash }`. `oaath deploy-runtime` now sends these prepared
transactions instead of keeping its own copy.
