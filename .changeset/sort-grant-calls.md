---
"@oaath/sdk": patch
---

`requestPermission` orders the expanded calls in the protocol's canonical target-selector order itself, so adopters no longer pre-sort multi-target permissions; a repeated target and selector still fails as `oaath_client_input_invalid`.
