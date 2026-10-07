# @oaath/dca

The HTTP-only TypeScript SDK for the Rust DCA API. The root has no runtime
dependencies and never polls the chain. The optional `/approval` entry supplies
owner consent orchestration. Neither entry holds a session signing key.

```ts
import { createDca } from "@oaath/dca";
import { createOwnerApproval } from "@oaath/dca/approval";

const dca = createDca({
  baseUrl: apiUrl,
  token: () => applicationAccessToken,
  approve: createOwnerApproval({
    journal: durableApprovalJournal,
    confirm: showExactTermsAndSetupCalls,
    signTypedData: value => wallet.signTypedData(value),
    executeSetup: async (calls, review) => {
      const operation = await ownerClient
        .account(review.terms.account).owner(wallet)
        .sendCalls({ chain: review.terms.chainId, calls });
      return { operationId: operation.id };
    },
  }),
});
const plan = await dca.create({
  account, chainId, sell: { token: USDC, amount: "25" },
  buy: { token: WETH }, intervalSeconds: 86400,
  maxRuns: 30, maxSlippageBps: 50, idempotencyKey: customerPlanId,
});
await dca.authorize(plan.id); // pending until setup is confirmed; service activates
const status = await dca.get(plan.id);
const { runs } = await dca.listRuns(plan.id);
await dca.pause(plan.id);
await dca.resume(plan.id);
const cancellation = await dca.cancel(plan.id);
```

`maxRuns` counts scheduled opportunities. Missed and finalized-failed purchases
are never made up. Review includes exact normalized base units, UTC start/end,
900-second admission grace, price feeds and freshness, minimum-output rule,
account recipient, service-held signer custody, zero service fee, account-paid
gas ceilings, executor setup and bounded token approval. Show **all** fields
and setup calls before `confirm` returns true. Test consumers auto-confirm
only their owned fixture wallet; a real application must obtain owner review.

The supplied approval flow uses your existing OAAth owner client/wallet.
`ApprovalJournal` requires durable atomic compare-and-swap. A recorded setup
attempt is never automatically repeated, even after a lost reply. The service
checks finalized setup directly; subsequent `authorize`/`submitApproval` calls
can submit retained consent. Missing evidence remains pending. If execution
never began but the journal cannot prove that, cancel and obtain fresh consent
for a new plan. Keep the owner client's durable operation store as well.

Cancellation can remain `cancelling`. Review `cancellation.calls` and submit
those calls through the same owner client. The service observes executor stop,
zero allowance and Grant revocation. Already submitted purchases remain visible.
Pause only controls service scheduling. An expired/completed plan can still be
cancelled to close remaining onchain authority.

Use application credentials in trusted application code. A browser integration
needs application-provided authenticated access; do not distribute a shared
server bearer token. `fetch`, token provider and timeout are injectable. HTTP
mutations are not automatically retried. `DcaError.code` is sanitized;
`request_outcome_unknown` requires reading retained status. Reusing the same
creation key with the same canonical inputs recovers the original plan.
