---
"@oaath/sdk": minor
---

Owner call review now estimates the complete call list, including explicitly
selected sponsorship, and returns single-operation capacity and gas facts.
An unavailable or rejected estimate cannot be reported as a successful review.
Review remains read-only: it does not prompt, sign, submit or reserve an
operation slot. Submission obtains a fresh quote through the existing journal.
