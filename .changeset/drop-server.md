---
"@oaath/protocol": patch
"@oaath/testing": patch
---

Remove `@oaath/server` and the service bootstrap document; the Rust relay owns authorization state. `parseWorkspaceAccountContext` stays in `@oaath/protocol`.
