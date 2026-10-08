# Local proof — 7 October 2026

The current [automation product evidence](automation-product.md) covers the
Rust API, TypeScript SDK, supplied React creator and DCA example. JSON files in
this directory retain sanitized results from the current local build.

These checks use owned Anvil and PostgreSQL fixtures, not a public chain or
live RPC provider. Package bytes and source commits are recorded in
[provenance](../vendor/provenance.json) and [checksums](../vendor/checksums.json).
