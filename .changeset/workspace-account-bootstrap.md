---
"@oaath/protocol": patch
"@oaath/sdk": patch
"@oaath/server": patch
---

Make bootstrap caller-dependent and add a versioned personal/team workspace and
account context. Deployments now provide `bootstrap.resolve(caller)`; static
bootstrap configuration is removed. Local realm and session identities include
the selected context and complete account profile, so context switching and
cleanup stay isolated. The bootstrap v4 and local binding/session v2 formats
replace their predecessors without migration; existing clients must reapprove.
