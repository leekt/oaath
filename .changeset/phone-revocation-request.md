---
"@oaath/protocol": patch
"@oaath/sdk": patch
---

Add a closed, versioned Kernel owner-phone revocation request and SDK preparation
helper. Requests bind the canonical permission, install scope and exact
chain-bound owner operation to an install-invalidation or permission-uninstall
effect. Completion verifies the phone signature without submitting anything.
The shared removal-call encoders now live in protocol and report
signing_request_invalid; SDK exports retain the current codec names.
