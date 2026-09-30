---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/server": patch
"@oaath/testing": patch
"@oaath/cli": patch
---

A session runtime now checks every call against the exact CallPolicy payload it installs, and refuses a call the chain would reject (an unnamed target or selector, a partial selector, or native value above the permission's limit) with the new `kernel_runtime_call_forbidden` code before any key is asked to sign. `prepareOperation`, `signOperation`, and `encodeVerifiedSignature` all refuse; client calls map the code to `oaath_client_scope_denied`.
