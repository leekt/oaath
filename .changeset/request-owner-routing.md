---
"@oaath/server": patch
---

Require explicit owner routing when creating authorization requests. Store the
approving device and its authenticated subject separately from the requesting
member, and preserve that route through approval and restart. Request records
and the relay PostgreSQL schema advance to v2 with no old reader or migration.
Directory admission and phone enrollment remain separate integration work.
