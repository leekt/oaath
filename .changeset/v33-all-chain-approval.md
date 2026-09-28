---
"@oaath/sdk": minor
---

Use Kernel 0.3.3's native replayable enable path so one owner approval authorizes
the same account, permission and validation nonce across chains. The runtime
signs enable operations with Kernel's chain-zero digest while preserving the
actual chain's EntryPoint hash in prepared operations. Installed sessions and
owners keep normal chain-specific signatures.

The v3.3 approval artifact is now v2 with chainScope "all"; previous chain-bound
records are rejected. Export kernelV33OperationSigningHash for external session
signers. High-level v3.3 Grant integration remains pending.
