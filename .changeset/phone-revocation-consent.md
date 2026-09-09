---
"@oaath/server": patch
---

Add the native v6 revocation consent projection and separate no-code decision
contract. The phone reviews exact removal operations, checks its paired account
and configured chain, and signs through the existing consent and retry flow.
Update relay and phone together; refetch earlier consent. This adds no revocation
queue, HTTP decision handler, operation submission, or finality claim.
