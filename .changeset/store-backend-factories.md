---
"@oaath/sdk": minor
"@oaath/testing": patch
"oaath": patch
---

Breaking: each store backend has one public factory that returns the full
store set. `@oaath/sdk/persistence` exports
`openIndexedDbStores({ factory?, name? })`, which returns `{ stores, close }`,
in place of `openOaathDatabase` and the seven `createIndexedDb*` adapters.
`@oaath/sdk/testing` exports `createMemoryStores()` in place of the seven
`createMemory*` adapters. Both are for the injected `binding` composition.
`createOAAth` options keep naming a backend in `stores`.
