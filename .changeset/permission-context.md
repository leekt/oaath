---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/server": patch
---

Bind the selected workspace/account context into PermissionRequest v2 and its
approval hash. SDK requests retain their connection's context, and resume rejects
a stored request from another context. Requests use one current encoding with
explicit null for frontend session custody. Previous request versions are rejected
and require fresh authorization; operation evidence is not migrated or deleted.
