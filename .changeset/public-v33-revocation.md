---
"@oaath/sdk": minor
---

Expose the existing Kernel v3.3 permission-state reader, decoder, status and
revocation-call planner through `@oaath/sdk/kernel`. Custom applications can
prepare the exact owner operation without duplicating Kernel module encodings.
Installed authority requires uninstall; unused authority requires atomic install
and uninstall to consume only that permission's enable nonce. Already absent and
invalidated authority produces no calls. Other permissions remain usable.

The caller pins the three permission reads to one canonical block and owns its
operation journal. Permission absence alone is not revocation proof: its
effective nonce must also exceed the retained approval's nonce. These exports
do not submit, retry or imply transaction finality and add no persisted shape.
