---
---

Enforce packed composition and public surface as real gates. `check-public-surface`
walks the transitive import graph across workspace edges from the `@oaath/sdk` and
`@oaath/protocol` root entries, so a `node:` or driver import added inside protocol
fails the sdk's browser graph too, and asserts the one-way production dependency
direction plus that no published entry resolves to `src`. `smoke-packed-browser`
and `smoke-packed-server` build, pack, and `npm install` the tarballs into clean
consumers outside the workspace and prove the golden path, realm recreation, the
relay round-trip, the Node-only `./postgres` subpath, and `nodenext` strict type
resolution against the published artifacts. The live-provider deny list moves to
its repo-owned home. `smoke-all-chain-anvil` stays a deliberate fail-closed stub.
No release.
