---
"@oaath/sdk": minor
---

Observe acknowledged direct EntryPoint transactions through public RPC after
reload without a connected wallet or bundler receipt index. A transaction hint
only locates the exact UserOperation event; the existing observer still verifies
inclusion and finality. Missing or failed transactions never authorize another
submission. Receipt and execution projections also use the known inclusion
transaction instead of requiring a bundler index.
