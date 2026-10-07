# Automation

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Rust API, TypeScript SDK, React with shadcn/ui (user-selected). A private TypeScript worker consumes OAAth. One repository contains the product and its DCA example.

## Users

Application developers integrate one authenticated session endpoint and the supplied creator. Their customers define and approve individual onchain automations.

## Product Purpose

Make integration require little AI context and application code. The hosted service owns scheduling and recovery; customers select explicit, supported terms. DCA is the first recipe and example.

## Capabilities and Constraints

Create, review, authorize, status, history, pause, resume and confirmed cancellation. An application chooses one hosted session signing key per user (default) or one shared within that application. Each plan retains independent authority and consent. Keys, accounts and application identities never come from unauthenticated claims. No public-chain deployment or package publication is requested.

## Operating Context

Local Anvil and PostgreSQL fixtures provide real Kernel and swap execution. Accessible previews remain private to Tailscale. Existing proofs are in evidence/; they are local measurements, not production claims.

## Product Principles

- End users create automations through guided fields; YAML is optional future import/export.
- Approval shows complete normalized terms, custody, limits and separate fees.
- Unknown submission never permits another send.
- Small SDK surface and precise errors reduce integration effort.
- OAAth owns authority and operations; Cetane owns primitives; Moesi owns deployment observation.
