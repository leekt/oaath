---
"@oaath/automation-server": patch
---

Add optional `AUTOMATION_RELAY_PAYS_GAS_<chainId>=true`: the chain's bundler pays gas (bundle_rs fast mode), so operations carry zero fees and use no paymaster. It is refused together with a paymaster URL.
