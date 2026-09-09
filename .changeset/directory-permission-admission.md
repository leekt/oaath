---
"@oaath/server": patch
---

Let the service directory admit permission requests and resolve the registered
account's owner device. Admission checks current membership, workspace/account
context, application identity, and the complete account profile. Selection changes
do not retarget requests; membership removal refuses new requests without changing
previously admitted routes or revoking existing grants.
