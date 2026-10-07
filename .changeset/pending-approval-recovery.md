---
"@oaath/sdk": patch
"@oaath/testing": patch
---

Persist encrypted pending service approvals before owner handoff. Resume the same request after reload, withdraw pending requests, and cancel waiting on close or AbortSignal. Atomic store revisions prevent duplicate one-time redemption across tabs; interrupted redemption remains explicitly uncertain.
