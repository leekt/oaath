---
"@oaath/sdk": patch
---

Use the upstream local Grant authorization path without an in-process issuer
transport. Keep the combined owner/session client, local-wallet signing, durable
custody and retryable cleanup. Add the decoded-policy callback before signing.

The local SDK configuration now takes `account: address`, matching the current
upstream API. Remove the earlier account descriptor and local issuer identity;
unreleased local-mode state must be recreated under the current identity.
