---
"@oaath/sdk": minor
---

Allow `webauthnKey` session authority through `createKernelRuntime` on an existing
Kernel 0.3.3 account. The ECDSA restriction belongs to root-owner binding; session
authority uses its independent signer module and existing permission envelope.
No new runtime, credential format, approval version or operation state is added.

One owner approval can enable the same passkey permission on multiple chains.
The enable signature uses Kernel's chain-zero digest; subsequent operations use
their chain-specific digest. Recreating the runtime and reading the installed
account does not reinstall authority or reset any nonce. Reusing a consumed
enable approval, signing the wrong digest and exceeding the call/value scope
remain rejected by the actual Kernel/EntryPoint path.

Local two-chain Anvil tests cover ECDSA and WebAuthn sessions, plus public packed
composition. Browser credential selection and Orchestra's durable application
grant/execution flow remain separate integration work; this change does not
claim those paths are complete.
