---
"@oaath/automation-server": patch
---

Activate an automation plan once its setup operation is included and successful, rather than finalized, so occurrences are no longer held for L1 finality. With a setup, occurrence slot N now runs on nonce lane N + 1, leaving lane 0 to the setup while it awaits finality. An authorized plan waits for its setup until its Grant ends and then expires with `setup_not_included`; a setup that fails, reverts or drops fails the plan even after activation; slots opening after the approved Grant's end are skipped as `grant_expired`. The schema is unchanged.
