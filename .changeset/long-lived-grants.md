---
"@oaath/sdk": patch
---

`requestPermission` accepts any Grant lifetime: `expiresIn` may be up to 2^42 seconds (about 139,000 years, effectively eternal) instead of one day.
