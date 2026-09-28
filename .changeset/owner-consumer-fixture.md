---
"@oaath/testing": patch
---

Expose `createLocalOwnerAnvilFixture` from `@oaath/testing/anvil` for clean
consumers of existing Kernel v3.3 owner execution. The fixture uses real local
contracts and public SDK APIs with browser/local wallets, a bounded bundler
fixture, and recreated SQLite operation storage. Its gas estimates are fixed
fixture limits; EntryPoint validation and execution run on Anvil. No hosted
RPC or bundler is contacted.
