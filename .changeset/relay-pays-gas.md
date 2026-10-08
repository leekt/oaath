---
"@oaath/sdk": patch
---

Add `relayPaysGas` to Cetane chain ports: a relay-paid bundler (such as bundle_rs in fast mode) receives zero-fee operations that need no account funds and no paymaster. It is refused together with `paymasterUrl`.
