---
"@oaath/sdk": patch
---

Depend on Cetane 0.0.6. Cetane chain ports quote fees with Cetane's default policy instead of their own base-fee multiplier, and `ecdsaKey` accepts accounts whose `address` is a getter, as Cetane 0.0.6's `privateKeyToAccount` returns.
