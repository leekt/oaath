---
"@oaath/protocol": patch
---

ECDSA owner and operator credential profiles (and existing Kernel account addresses) now accept a valid EIP-55 checksummed address and capture it in canonical lowercase, so canonical encodings and hashes match the lowercase spelling. Mixed-case addresses with an invalid checksum are still rejected.
