---
"@oaath/sdk": patch
---

A failed signing capability (wallet `signMessage`, `account.sign`, P-256, WebAuthn, or a wallet approval prompt) now keeps the wallet's own error as the standard `cause` on the thrown OAAth error, so callers can read an EIP-1193 code such as 4001 without OAAth copying provider text into its message. Error codes are unchanged.
