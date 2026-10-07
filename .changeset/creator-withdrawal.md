---
"@oaath/server": patch
---

Allow authenticated creators to withdraw pending authorization requests atomically with owner decisions. Approved requests remain approved. The current decision record is v2 and PostgreSQL schema is v5; recreate obsolete schemas.
