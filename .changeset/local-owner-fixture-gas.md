---
"@oaath/testing": patch
---

Allow enough verification gas in the local v3.3 fixture to install a multi-call
session permission on ordinary EVM chain IDs. The regression executes an owner
operation, installs a larger permission, then reopens the SDK and reuses it
without another approval. Production bundler estimation is unchanged.
