---
"@oaath/server": patch
---

Verify grant references against the retained permission approval's policy,
calls and expiry instead of the originally requested policy. Missing, unbound,
widened or unreadable approval evidence returns unknown. Verification reads the
existing sealed artifact without claiming or releasing it, including after
client claim and restart. Custom RelayTransaction adapters must implement the
request-indexed artifact read; no stored schema changes.
