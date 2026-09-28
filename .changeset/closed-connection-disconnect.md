---
"@oaath/sdk": patch
---

Remove successfully closed connections from the realm's active set. Disconnect
can then sign out after short-lived permission/review connections were closed,
including when no connection remains open. A failed connection close stays
registered for retry; closing never substitutes for issuer sign-out.
