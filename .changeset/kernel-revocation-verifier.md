---
"@oaath/sdk": minor
---

Add `verifyKernelPermissionRevocation` to `@oaath/sdk/kernel`: a stateless,
read-only check of one issued Kernel v3.3 or v4 Grant approval on one chain. It
dispatches on `approval.version`, reads through a caller-owned finalized
observation capability (for example a chain port's `observation`), and returns
`revoked` with the same `ChainRevocationEvidence` the SDK records, `active`,
`approval-replayable` (absent, but the enable nonce is unused), or `unreadable`
for any transport, finality, chain or state failure. It never signs, submits or
retries.

The SDK's own Grant revocation now uses the same owner. A v3.3 enable nonce is
compared as Kernel's uint32 validation nonce; EntryPoint nonce keys, including
custom uint16 lanes, are never consulted. A v4 install nonce under another
install key is now `unreadable`, not merely not revoked.
