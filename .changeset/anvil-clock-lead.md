---
"@oaath/testing": patch
---

The local Anvil fixture starts its chain clock one second ahead of wall time.
Anvil's implicit genesis timestamp could leave every block a second behind,
so a Grant whose validity starts at the current wall-clock second was
occasionally rejected as not yet due on its first operation.
