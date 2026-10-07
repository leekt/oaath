# Arbitrum Sepolia deployment

`https://dca.taek.tech` hosts the wallet-connected DCA example. Cloudflare serves three static assets and forwards authenticated application requests through the dedicated `dca-api` VPC service. The existing OCI tunnel reaches only `127.0.0.1:4320`. The example application gateway, Rust Automation API (4317), and TypeScript execution worker (4318) run as dedicated `dca-*` systemd services on OCI. PostgreSQL and signer sealing keys remain private. This deployment does not depend on a running development Mac.

The gateway is the example application's identity boundary, not a replacement for the Rust product API. A short-lived, one-use wallet challenge binds the domain, chain, owner, nonce and expiry. The backend derives the owner's Kernel v4 account and creates its user-scoped API session. An HttpOnly, Secure, SameSite cookie selects that session. Application credentials and the ZeroDev project endpoint never enter static assets. Public routes exclude application administration, private files, and the local fixture owner bridge.

## Pinned testnet profile

See `arbitrum-sepolia.json`. Addresses come from [Uniswap's Arbitrum deployment table](https://developers.uniswap.org/docs/protocols/v3/deployments/v3-arbitrum-deployments), [Circle's USDC addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses), and [Chainlink's Arbitrum Sepolia reference data](https://reference-data-directory.vercel.app/feeds-ethereum-testnet-sepolia-arbitrum-1.json). Token metadata is USDC 6 decimals, WETH 18; feed metadata is 8 decimals. The route is the 0.3% Uniswap v3 pool through SwapRouter02. These are test assets and testnet market prices.

The DCA factory is `0x6d2186dc7f7e973b9bc11235dadbf0147f76133e`. Owner setup creates a dedicated immutable executor and an allowance bounded by the total approved USDC input. The session can only execute that executor. Each purchase checks the slot, recipient, exact spend and feed-derived minimum output. Both feeds must be positive, round-consistent, and no older than 86,400 seconds; this ceiling accommodates the testnet USDC feed's daily heartbeat and is shown in owner review. Production oracle choices remain out of scope.

Gas is paid by the account. The approved runtime ceilings are 1 gwei per gas and 0.001 test ETH per operation; service fee is zero. No sponsorship is configured. The worker has a shared 3,000-method/10-minute process budget. The gateway separately retains a 3,000-method/10-minute PostgreSQL budget and 500-method/10-minute per-owner cap, including across restarts. Idle account views and plan status use stored data; account balance refresh is explicit.

## Reproduce or update

1. Install the pinned dependencies and run `bun run check` plus the applicable local contract/purchase proof. Build the Rust binary locally using `cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.35`; the small OCI host does not build Rust.
2. For an explicitly authorized testnet contract deployment, retain the deployment-only signer in `.local/hosting/testnet-deployer.json` and project configuration in `.local/hosting/zerodev.json`, both mode 0600. Run `DCA_TESTNET_DEPLOY=421614 bun deploy/testnet.ts`. It checks chain, deployer and runtime hashes, bounds requests/gas, and retains the signed transaction and hash before broadcasting. An attempted transaction is observed, never automatically resent.
3. Run `bun deploy/build.mjs`. Upload only `dist/server`, the Linux API binary, generated private `deployment.json` and `install.py` into a private staging directory at `/tmp/dca-release` on OCI. Run the installer as root. The installer creates only DCA-owned resources, retains existing secrets, waits for API migrations, and enables all three services. Do not overwrite `/etc/dca/runtime.env` or its sealing key.
4. Run Wrangler with `deploy/wrangler.jsonc`. It preserves all unrelated tunnel/VPC services and Serve mappings. Verify HTTPS, wallet login, forbidden origins/routes, account setup, consent and execution. Contract verification and purchases require authoritative finality; a transaction hash alone is not success.

The deployment key is for test deployment and the explicit hosted proof, never customer signing. Users retain their owner wallets; service-held session credentials are separately scoped and sealed. Wallet account setup, plan setup/allowance and cancellation are distinct, visible owner actions. Pause stops new scheduling; cancellation confirms onchain effects and Grant revocation.

## Current proof boundary

The public shell, wallet login, smart-account creation, funding and retained sessions/plans across service restart are verified. The DCA factory is deployed and finalized. Public owner setup remains unresolved after ZeroDev rejected an operation whose estimate contained zero verification gas. The SDK now rejects that unusable estimate before publication; it never turns the missing receipt into resend permission. Public purchase and cancellation proofs remain incomplete. See `evidence/hosted-testnet.md` and `evidence/verification-gas.md` for evidence and limits.
