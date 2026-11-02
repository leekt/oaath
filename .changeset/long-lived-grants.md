---
"@oaath/sdk": patch
---

`requestPermission` accepts any Grant lifetime: `expiresIn` may be up to 2^47 seconds (about 4.4 million years, effectively eternal) instead of one day.
