The DCA recipe now calls the pinned Uniswap SwapRouter02 `exactInputSingle` interface. Its seven-word tuple has no deadline field; the executor still rejects execution outside the approved slot and grace window before calling the router.

Validation on 8 October 2026: all 20 Forge regressions passed. The packed public SDK completed a real Kernel v4 / EntryPoint 0.9 purchase against the exact `@uniswap/swap-router-contracts@1.1.0` artifact on owned Anvil, with PostgreSQL and the existing Operation runner. The proof retained finalized successful executor and swap evidence. Typecheck, lint, 39 TypeScript tests and workspace builds passed.

This local proof does not measure public provider performance. Arbitrum Sepolia deployment and hosted wallet evidence are recorded separately.
