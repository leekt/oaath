---
"@oaath/sdk": patch
"@oaath/automation": patch
---

Accept a bundler's `paymasterPostOpGasLimit` estimate in ERC-7677 sponsorship (validated, never replacing the paymaster's own post-op limit), and make the automation client refuse redirects with `redirect: "manual"` so it works inside Cloudflare Workers.
