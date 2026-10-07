---
"@oaath/server": patch
"@oaath/sdk": patch
---

Retain hosted session signer identity with a versioned PostgreSQL registry. Creation is explicit; recovery and signing require the expected public credential and never replace missing custody. The service SDK persists creation intent and public credential before consent and recovers them across reloads.
