---
"@oaath/sdk": patch
---

Grant requests can name the app's own read-only JSON-RPC per chain (`rpcUrls` on `requestPermissionApproval` and on OAuth `approvals`); the OAAth portal reads that chain through it to prepare the root's approval. Keys must be requested chain IDs and URLs https; they are visible to the user.
