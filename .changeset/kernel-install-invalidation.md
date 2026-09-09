---
"@oaath/sdk": patch
---

Expose Kernel install nonce read and invalidation codecs for owner integrations.
An owner self-call can invalidate one unused approval on a destination chain
without advancing other install keys or the account's global minimum. These
codecs do not replace installed-permission removal or revocation observation.
