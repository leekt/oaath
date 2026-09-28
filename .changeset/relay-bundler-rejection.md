---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/server": minor
---

Preserve closed bundler pre-acceptance rejection evidence across relay submission
errors so URL-only Grant clients can use the connected EOA fallback. One protocol
owner captures the allowlisted numeric code; the relay forwards no provider prose
or raw data. Only the submission endpoint can authorize this fallback. Generic
HTTP failures, unknown codes and malformed evidence remain observation-only.
