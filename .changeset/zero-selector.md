---
"@oaath/protocol": patch
---

`parseGrantPolicy` accepts any lowercase 4-byte selector, including `0x00000000`: a target without function dispatch (the CREATE2 deployer) takes its first calldata bytes from data such as a salt, and Kernel's call policy matches them all the same.
