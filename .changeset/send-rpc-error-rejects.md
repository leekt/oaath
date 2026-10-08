---
"@oaath/sdk": patch
"@oaath/protocol": patch
---

A well-formed JSON-RPC error answer to `eth_sendUserOperation` now concludes the attempt as rejected: the Operation is abandoned with reason `submission_rejected`, its lane is released, and the caller receives `OaathClientError` code `oaath_client_submission_rejected` with the bundler's numeric `rpcCode`. Timeouts, transport failures and malformed answers remain uncertain and observation-only. Nothing is resubmitted.
