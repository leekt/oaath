---
"@oaath/sdk": patch
---

Expose read-only `Operation.execution()` with finalized sender and exact ordered calls decoded from the containing EntryPoint transaction and bound to the retained operation hash. Observation adapters supply the new `transaction_execution` read. Unsupported or mismatched evidence fails closed; no signature or provider lifecycle state is exposed.
