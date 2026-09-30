---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Accept and normalize valid EIP-55 addresses in public UserOperation references. Reject invalid checksums with a specific structured error before observation reads; persisted operation records remain canonical.
