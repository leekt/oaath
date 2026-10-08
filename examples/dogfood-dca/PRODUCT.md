# Automation

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Rust API, TypeScript SDK, React with shadcn/ui (user-selected). A private hosted TypeScript worker consumes OAAth; a DCA recipe contract bounds execution. One repository contains the product and its DCA example. The hosted example adds a wallet-authenticated application gateway and uses ZeroDev for its Arbitrum Sepolia account-abstraction transport.

## Users

Application developers integrate one authenticated session endpoint and the supplied creator. Their customers define and approve individual onchain automations.

## Product Purpose

Make integration require little AI context and application code. The hosted service owns scheduling and recovery; customers select explicit, supported terms. DCA is the first recipe and example.

## Capabilities and Constraints

Create, review, authorize, status, history, pause, resume and confirmed cancellation. An application chooses one hosted session signing key per user (default) or one shared within that application. Each plan retains independent authority and consent. Keys, accounts and application identities never come from unauthenticated claims. The user authorized public deployment of the connected-wallet DCA example at `https://dca.taek.tech` on Arbitrum Sepolia. Package publication remains out of scope.

Hosted login binds the domain, chain, owner, one-use nonce and expiry. The gateway derives the owner's counterfactual smart account; a separate wallet transaction creates it. Customers fund the smart account with test ETH and test USDC, then use the supplied creator to review and approve exact plan terms. Login, account creation and plan spending approval are distinct actions.

## Operating Context

Local Anvil and PostgreSQL fixtures provide real Kernel and swap execution. Development previews remain private to Tailscale by default; the explicitly authorized hosted example is public and testnet-only. Existing proofs in `evidence/` are local measurements, not production claims.

Hosted verification has covered wallet login, smart-account setup and funding, plus retained sessions and plans after all services restart. Public plan setup is blocked by inconsistent ZeroDev verification-gas estimates and an unresolved submission. OAAth now rejects zero effective verification gas before publication. A completed public purchase and confirmed public cancellation are not established. UI review captures verify presentation and interaction states, and do not establish chain finality.

## Product Principles

- End users create automations through guided fields; YAML is optional future import/export.
- Approval shows complete normalized terms, custody, limits and separate fees.
- Unknown submission never permits another send.
- Small SDK surface and precise errors reduce integration effort.
- OAAth owns authority and operations; Cetane owns primitives; Moesi owns deployment observation.
