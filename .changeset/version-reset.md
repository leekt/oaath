---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/testing": patch
"@oaath/cli": patch
---

Reset every protocol and SDK wire, profile and record version to `v1`, and rename `service_bootstrap_invalid` to `workspace_account_context_invalid`. Records written under the old versions are rejected; recreate them.
