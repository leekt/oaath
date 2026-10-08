---
"@oaath/sdk": patch
---

Coalesce identical concurrent reads and endpoint chain checks within one Cetane RPC pool. Sends, estimates and paymaster requests are never combined, sequential reads always fetch fresh evidence, and the lifetime budget counts actual wire requests.
