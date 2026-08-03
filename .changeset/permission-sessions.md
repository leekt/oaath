---
---

Scope @oaath/sdk Kernel sessions through permission composition: one policy
package per bounded axis — the calls and their value, the validity window, the
per-chain operation count — then the permission signer carrying the session key.
The permission signature envelope carries one slice per installed policy package,
as Kernel's permission validation requires. No release.
