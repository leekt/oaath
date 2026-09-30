---
"@oaath/sdk": patch
---

`createKernelReads` serves an `entry_point_lane_nonce` read (EntryPoint 0.7
`getNonce(account, key)`), and `@oaath/sdk/advanced` exports
`readKernelLaneSequence({ account, key, reads })` next to
`encodeKernelNonceKey`. It returns a nonce lane's next sequence for
`prepareOperation`. An unreadable result fails with
`kernel_runtime_read_unavailable`; a result for another key or a malformed one
fails with `kernel_runtime_evidence_invalid`.
