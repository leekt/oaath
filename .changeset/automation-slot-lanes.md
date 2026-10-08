---
"@oaath/automation-server": patch
"@oaath/sdk": patch
---

Run each automation occurrence on its own Kernel nonce lane, so a due slot no longer waits for the previous slot's finality. At most `AUTOMATION_MAX_OPEN_SLOTS` (default 4) occurrences of one plan are open at once. The automation schema is now `oaath.automation-postgres-schema/v2`; drop and recreate the automation database. An explicit SDK operation lane may now start once the Grant's installing operation is included, rather than finalized, and runs in standard mode.
