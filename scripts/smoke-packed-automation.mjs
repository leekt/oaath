/**
 * Owns: the packed `@oaath/automation` and `@oaath/automation-server`
 * artifacts work for a clean npm consumer.
 *
 * The consumer installs the tarballs only, typechecks against the published
 * declarations, derives a plan and its Grant policy through the public schema
 * owner, and starts the published `oaath-automation` bin, which must refuse a
 * missing configuration by naming the variable. No database, chain or issuer
 * is contacted.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "automation",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/automation", "@oaath/automation-server"],
  types: ["node"],
  skipLibCheck: true,
  dependencies: { "@types/node": "22.13.0" },
  files: {
    "consumer.ts": `import { createAutomation, defineAutomation, derivePlanPolicy, type Plan } from "@oaath/automation";
import { createAutomationServer } from "@oaath/automation/server";
import { configFromEnv, startAutomationService, type AutomationServiceConfig } from "@oaath/automation-server";
const definition = defineAutomation({
  id: "ping.v1", name: "Ping", chainId: 1,
  contracts: { target: { address: "0x1111111111111111111111111111111111111111", abi: [] } },
  schedule: { every: "1h", count: 3 },
  call: { contract: "target", function: "ping" },
});
const client = createAutomation({ baseUrl: "https://automation.example", token: "t" });
const server = createAutomationServer({ baseUrl: "https://automation.example", token: "t" });
const start: (config: AutomationServiceConfig) => Promise<unknown> = startAutomationService;
const plan: Promise<Plan> = client.get("0x" + "ab".repeat(32));
void [definition, server, start, plan, configFromEnv, derivePlanPolicy];`,
    "consumer.mjs": `import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPlanTerms, defineAutomation, derivePlanPolicy, resolveCalls } from "@oaath/automation";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
const definition = defineAutomation({
  id: "ping.v1", name: "Ping", chainId: 1,
  contracts: { target: { address: "0x1111111111111111111111111111111111111111", abi: [
    { type: "function", name: "ping", inputs: [{ name: "slot", type: "uint32" }], outputs: [], stateMutability: "nonpayable" },
  ] } },
  schedule: { every: "1h", count: 3 },
  call: { contract: "target", function: "ping", args: ["$slot.index"] },
});
const terms = createPlanTerms(definition, {
  planId: "0x" + "ab".repeat(32), account: "0x2222222222222222222222222222222222222222", now: 1800000000,
});
const policy = derivePlanPolicy(definition, terms, 1800000000);
assert.equal(policy.calls.length, 1);
assert.equal(policy.perChainOperationLimit.count, 3);
assert.equal(resolveCalls(definition, terms, { slot: 2 })[0].data.slice(0, 10), policy.calls[0].selector);
const bin = spawnSync(process.execPath, ["node_modules/@oaath/automation-server/dist/cli.mjs"], {
  encoding: "utf8", env: { PATH: process.env.PATH },
});
assert.equal(bin.status, 1);
assert.match(bin.stderr, /config_invalid:AUTOMATION_SEAL_KEY/);
console.log("Packed automation schema, client and service bin work for a clean consumer.");`,
  },
});
try {
  consumer.typecheck();
  console.log(consumer.node("consumer.mjs").trim());
} finally {
  await consumer.cleanup();
}
