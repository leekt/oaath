# All-chain example — approve before chain B exists

One owner signature, two chains, no second approval.

```sh
pnpm --filter @oaath/examples example:all-chain
```

Requires Anvil ([Foundry](https://getfoundry.sh), or set `ANVIL_PATH`). The
example says so and exits non-zero when it is missing. Two chains plus the full
Kernel v4 stack takes roughly 20 seconds.

## The journey

1. **Chain A comes up.** Anvil, EntryPoint 0.7, both Kernel v4 implementations, the
   factory, the pinned policy and signer modules, and one ECDSA validator — every
   one of them CREATE2-derived. The session runtime binds a counterfactual account
   from the *owner's* initial packages.
2. **The owner approves once.** `approveKernelPermissionAllChain` signs Kernel v4's
   replayable enable digest, whose EIP-712 domain omits the chain id and binds only
   the account, Kernel's install nonce, and the exact install packages. It reads no
   chain and no deployment profile, so nothing about it can depend on a chain —
   least of all one that does not exist yet. The example reproduces the digest from
   the approval's own fields to show it is chain-independent.
3. **Chain A executes.** `materializeKernelPermission` spends that signature: one
   submission deploys the account, installs the scoped permission, and executes the
   covered call. The owner signs no UserOperation at all.
4. **Chain B is introduced.** A second Anvil, a different chain id, started *after*
   the approval exists. Same stack, same addresses, and therefore the same account
   address and the same installed packages — the example asserts all three rather
   than assuming them.
5. **The same signature materializes on B.** The identical `approval` object goes
   in, the owner's signature bytes appear verbatim inside the submitted envelope,
   and the covered call executes. The owner signature count, kept on the credential
   itself, is still `1`.

## What is all-chain and what is not

Authority is all-chain; evidence is not. The example asserts that the two chains
produce **different** operation identities from the same approval: the EntryPoint
nonce, the operation hash, inclusion, and revocation evidence are all chain-local
and no chain may borrow another's. There is no global atomic install, execute, or
revoke, and `perChainOperationLimit` is per chain by name.

The scope is a session scope, not account authority: the permission installs a
call policy for one `(target, selector)` pair and a value ceiling. A call the
policy never named is refused inside Kernel's validation phase —
`packages/sdk/test/all-chain.anvil.test.ts` asserts that refusal by its error
class, which is the negative half of this example and the reason the example
itself stays a walkthrough.

## Relationship to the SDK's own proof

This example is the narrated version of `packages/sdk/test/all-chain.anvil.test.ts`,
which is the authoritative proof and also runs as `pnpm smoke:all-chain`. The Anvil
harness in [../support/anvil.mjs](../support/anvil.mjs) is a minimal inlined copy of
that suite's `test/support/anvil.ts`; both collapse into `@oaath/testing`'s chain
fixtures when that package's `anvil.ts` lands, and the marker for that
consolidation lives in the SDK harness header. The deployment bytecode has no
published home yet, so the copy here reads the SDK's own deployment fixture rather
than keeping a second copy of it.
