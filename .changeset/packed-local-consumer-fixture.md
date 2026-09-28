---
"@oaath/testing": patch
---

Expose a Node-only `@oaath/testing/anvil` fixture that owns real local Kernel/EntryPoint chains, test authorization, reopenable client storage, and cleanup. External consumers can prove all-chain execution and operation recovery from public packed packages without copying OAAth transports or credentials. Requires the local Anvil executable; never a production dependency.
