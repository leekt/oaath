---
"@oaath/protocol": patch
---

Accept canonical selector-prefixed raw calldata in Grant policy coverage without requiring ABI word alignment. CREATE2 factory salt-plus-bytecode calls can now use a covered session policy. Selector, target, value, validity, usage, and complete constrained argument words remain enforced. Calldata shorter than four bytes remains unsupported by this coverage boundary.
