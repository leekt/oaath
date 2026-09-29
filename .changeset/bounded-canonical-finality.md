---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Recover old UserOperation receipts within a fixed RPC request budget. The shared
observer checks canonical inclusion against the configured RPC's finalized head,
then rebinds that head by number. It no longer reads every intervening block.
Missing, inconsistent or insufficient finality stays unresolved and never
authorizes resubmission. RPC chain evidence is not a local consensus proof.

Breaking advanced API change: remove the unused `block_by_hash` observation
request. Custom adapters must answer `canonical_block` by canonical height and
`finalized_block` with the actual finalized tag. No persisted record shape or
version changes.
