---
"@oaath/automation-server": patch
"@oaath/automation": patch
---

The service sends its plan's user and account as the issuer's `login_hint` (`<signer_id>@<account>`), so the OAAth portal opens on the review with no signer or account picker. A session's `userId` is the user's OAAth signer id.
