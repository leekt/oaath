# @oaath/automation

Two integration points: your authenticated backend issues a session; your React
page renders the supplied creator. End users choose terms and approve with their
wallet. DCA (`dca.v1`) is the first supported recipe.

```ts
// Backend only. Derive both values from YOUR authenticated customer/account.
import { createAutomationServer } from "@oaath/automation/server";
const automation = createAutomationServer({ baseUrl: API_URL, token: API_KEY });
// Optional application setting, default "user". This is onchain signing custody.
await automation.configureSigning({ keyScope: "user" }); // or "application"
return automation.createSession({ userId: customer.id, account: customer.account });
```

```tsx
// Browser. Memoize client/owner for the lifetime of the mounted integration.
import { createAutomation } from "@oaath/automation";
import { createWalletOwner } from "@oaath/automation/wallet";
import { AutomationCreator } from "@oaath/automation/react";
import "@oaath/automation/styles.css";

const session = await fetch("/your/authenticated/automation-session", {
  method: "POST",
}).then(r => r.json());
const client = createAutomation({ baseUrl: API_URL, token: session.token });
const owner = createWalletOwner({ provider: connectedEip1193Wallet, chains });
// chains: your existing OAAth public RPC/bundler descriptors for the configured chain.
// Account must already be a supported Kernel account owned by this wallet.
<AutomationCreator client={client} owner={owner} />;
// When the integration unmounts: await owner.close().
```

Sessions last one hour and are bound to application, user and account. Refresh
through your authenticated backend. A token callback can provide a refreshed
session token. Never accept unauthenticated user/account claims or expose the
application API credential. Per-user keys are scoped by stable customer ID,
not account address; application keys never cross applications.

For a custom UI, the same small HTTP client exposes:

```ts
const plan = await client.create({
  recipe: "dca.v1", amount: "25", opportunities: 30,
  maxSlippageBps: 50, idempotencyKey: stableCustomerRequestId,
});
const authorization = await client.authorize(plan.id); // review, no automatic signing
// Display the exact review, then obtain an explicit owner action:
if (authorization.review) {
  const evidence = await owner.approve(authorization.review);
  await client.submitApproval(plan.id, evidence); // active or setup pending
}
await client.get(plan.id);
await client.listRuns(plan.id);
await client.pause(plan.id);
await client.resume(plan.id);
const stopped = await client.cancel(plan.id); // stops admission immediately
if (stopped.cancellation?.status === "owner_action_required") {
  // Explain and confirm the onchain cancellation, then:
  await owner.cancel(stopped);
}
```

`opportunities` counts scheduled slots, not completed purchases. `/config`
returns the pinned pair, chain, daily interval, grace and fees. Amounts are
normalized before consent. A changed plan needs new consent. Reuse creation's
idempotency key only for identical inputs, including user and key scope.

The browser root is HTTP-only. React is an optional peer for `/react`; OAAth is
an optional peer for `/wallet`. IndexedDB stores owner action intents before
submission. Lost replies never trigger a second send. A pending operation stays
pending until independently observed; reopening a page does not rotate keys.

For other wallet hosts use `/approval` and `/cancellation` with an atomic durable
journal and the existing OAAth owner sendCalls path. `approve()` assumes the
calling UI has shown and explicitly accepted the complete owner review.
