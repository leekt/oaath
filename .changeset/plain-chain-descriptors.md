---
"@oaath/sdk": minor
"@oaath/testing": patch
---

`createOAAth` accepts plain `chains` descriptors keyed by chain ID, for example
`{ 143: { publicRpcUrls, bundlerUrl, paymasterUrl?, gas? } }`
(`OaathChainDescriptor`, the `createViemChainPorts` input), and builds the
default viem chain ports internally with the default request budget. The quick
starts no longer import `@oaath/sdk/viem`. An `OaathChainCapability[]`
(including an explicit `createViemChainPorts(...)` result with custom budget,
retry, or `fetch` options) is still accepted as the override. An invalid
descriptor fails with `oaath_client_input_invalid` (source
`oaath_rpc_config_invalid`). The testing Anvil owner fixture adds
`chainDescriptors()`, which serves its bundler over loopback HTTP.
