# @oaath/automation

Declarative automations for OAAth Grants, and the client of an automation
service ([`@oaath/automation-server`](../automation-server)).

An automation is data: the contracts it calls, typed parameters, a bounded
schedule, and the calls themselves. There is no scripting. An argument is a
literal or one reference: `$plan.id`, `$plan.account`, `$plan.startAt`,
`$plan.endAt`, `$plan.every`, `$plan.grace`, `$plan.occurrences`,
`$slot.index`, `$slot.at`, `$param.<name>` or `$contract.<name>`.

```ts
import { defineAutomation } from "@oaath/automation";

export default defineAutomation({
  id: "ping.v1",
  name: "Hourly ping",
  chainId: 421614,
  contracts: { target: { address: "0x…", abi: [pingAbiItem] } },
  schedule: { every: "1h", count: { max: 24 }, grace: "5m" },
  call: { contract: "target", function: "ping", args: ["$plan.id", "$slot.index"] },
});
```

`setup` calls run once as the first operation and `cancel` calls run once when a
plan is cancelled. Functions must be declared exactly once in the given ABI and
take static elementary types (`address`, `bool`, `bytes32`, `uintN`). Values
default to `"0"` and never exceed `limits.valuePerCall`. See
[`examples/dca`](../../examples/dca) for a complete definition.

## Plans and their Grant

A plan freezes one definition, its parameters and schedule
(`createPlanTerms`, `hashPlanTerms`). `derivePlanPolicy` turns them into the
Grant policy the account root approves in the issuer's portal:

- a call allow-list of exactly the declared contract functions (target and
  selector);
- validity from authorization until the schedule's last window closes;
- an operation count of the occurrences, plus one each for setup and cancel.

OAAth 0.3.x Kernel policies cannot pin arguments, so a definition's frozen
arguments are enforced by the service and by the called contracts, not by the
account. Design contracts accordingly. Editing a definition affects only new
plans.

## Client

```ts
// Your backend, with the application credential:
import { createAutomationServer } from "@oaath/automation/server";
const automation = createAutomationServer({ baseUrl: AUTOMATION_URL, token: APPLICATION_KEY });
// userId is the OAAth signer id from the verified id_token (`signer.id`).
const session = await automation.createSession({ userId: idToken.signer.id, account: idToken.sub });

// The browser, with the session token only:
import { createAutomation } from "@oaath/automation";
const client = createAutomation({ baseUrl: AUTOMATION_URL, token: session.token });
const plan = await client.create({
  automation: "ping.v1", occurrences: 24, idempotencyKey: crypto.randomUUID(),
});
const { authorizationUrl } = await client.authorize(plan.id, { returnTo: location.href });
location.assign(authorizationUrl); // the root approves the exact policy in the portal
```

Status and history (`get`, `list`, `runs`) are the service's retained
projections. `pause` stops new occurrences, `resume` restarts them, and `cancel`
stops admission and runs the definition's cancel calls. A request whose reply is
lost fails as `request_outcome_unknown` and is never retried.
