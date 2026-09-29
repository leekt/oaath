---
"@oaath/sdk": minor
---

Breaking: one Kernel error vocabulary. `OaathKernelV4Error` and the
`kernel_v4_*` codes are removed. Every Kernel entry point throws
`OaathKernelRuntimeError`, which gains two codes:
`kernel_runtime_chain_unsupported` and `kernel_runtime_evidence_invalid`.
Invalid input now reports `kernel_runtime_input_invalid` and an unavailable read
reports `kernel_runtime_read_unavailable`, whatever the Kernel version.
