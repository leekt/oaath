---
"@oaath/sdk": patch
---

Depend on Cetane 0.0.7. A chain port with `relayPaysGas` now takes its zero fees from Cetane's relay-paid fee policy (`chain.fees.relayPaysGas`) instead of its own override; quotes are unchanged and still make no fee reads.
