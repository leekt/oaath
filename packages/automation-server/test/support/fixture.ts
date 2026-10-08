import { createHash } from "node:crypto";
import { type AutomationDefinition, defineAutomation } from "@oaath/automation";
import type { AutomationServiceConfig } from "../../src/config.js";
import type { ServiceContext } from "../../src/context.js";
import { createPool, initializeSchema } from "../../src/db.js";

export const TOKEN = "0x1111111111111111111111111111111111111111" as const;
export const VAULT = "0x2222222222222222222222222222222222222222" as const;
export const ACCOUNT = "0x3333333333333333333333333333333333333333" as const;
export const APP_TOKEN = "application-credential-for-tests";

const fn = (name: string, inputs: string[]) => ({
  type: "function",
  name,
  stateMutability: "nonpayable",
  inputs: inputs.map((type, index) => ({ name: `a${index}`, type })),
  outputs: [],
});

export const definition: AutomationDefinition = defineAutomation({
  id: "recurring.v1",
  name: "Recurring call",
  chainId: 31337,
  contracts: {
    token: { address: TOKEN, abi: [fn("approve", ["address", "uint256"])] },
    vault: {
      address: VAULT,
      abi: [
        fn("open", ["bytes32", "uint256"]),
        fn("execute", ["bytes32", "uint32"]),
        fn("cancel", ["bytes32"]),
      ],
    },
  },
  params: { budget: { type: "uint256", min: "1" } },
  schedule: { every: 3600, count: { max: 10 }, grace: 600 },
  setup: [
    { contract: "token", function: "approve", args: ["$contract.vault", "$param.budget"] },
    { contract: "vault", function: "open", args: ["$plan.id", "$param.budget"] },
  ],
  call: { contract: "vault", function: "execute", args: ["$plan.id", "$slot.index"] },
  cancel: [{ contract: "vault", function: "cancel", args: ["$plan.id"] }],
});

export function testConfig(
  databaseUrl: string,
  overrides: Partial<AutomationServiceConfig> = {},
): AutomationServiceConfig {
  return {
    databaseUrl,
    sealKey: Buffer.alloc(32, 7),
    publicUrl: "http://127.0.0.1:4317",
    listen: { host: "127.0.0.1", port: 0 },
    issuer: "http://127.0.0.1:1",
    clientId: "automation-test-client",
    applications: [
      { id: "app", tokenSha256: createHash("sha256").update(APP_TOKEN).digest("hex") },
    ],
    allowedOrigins: ["http://localhost:5173"],
    definitions: [definition],
    chains: new Map([
      [
        31337,
        {
          rpcUrl: "http://127.0.0.1:1",
          bundlerUrl: "http://127.0.0.1:2",
          paymasterUrl: null,
          paymasterApiKey: null,
        },
      ],
    ]),
    budgets: { rpc: 10, bundler: 10, paymaster: 10, windowSeconds: 60 },
    ...overrides,
  };
}

/** A context with a controllable clock; chain ports are never built by these tests. */
export async function testContext(
  databaseUrl: string,
  clock: { now: number },
  replicaId = "replica-a",
  overrides: Partial<AutomationServiceConfig> = {},
): Promise<ServiceContext> {
  const config = testConfig(databaseUrl, overrides);
  const pool = createPool(databaseUrl);
  await initializeSchema(pool);
  return {
    config,
    pool,
    definitions: new Map(config.definitions.map((entry) => [entry.id, entry])),
    chain: () => {
      throw new Error("chain_not_used_in_tests");
    },
    budgetRetryAt: () => null,
    now: () => clock.now,
    replicaId,
  };
}
