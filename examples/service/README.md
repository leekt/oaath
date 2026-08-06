# Reference service deployment

One process serves the `@oaath/server` relay over real HTTP with real chain
execution ports (a local Anvil with the reviewed Kernel stack), an in-process
owner console signs the replayable install approvals, and a URL-only client
completes the whole golden path against it:

```ts
const oaath = createOAAth({ url });
```

A production deployment replaces exactly three things: the in-memory store
with PostgreSQL, the demo bearer tokens with its own authentication port, and
the local Anvil chain with its RPC/bundler endpoints. Nothing about the
client changes.

```sh
node --import ../support/workspace-typescript.mjs run.mjs
```
