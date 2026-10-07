/** Exercise the product deployment gate against its owned local fixture. */
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const settings = JSON.parse(readFileSync(".local/environment.json", "utf8"));
const deployment = JSON.parse(readFileSync(settings.AUTOMATION_CONFIG, "utf8"));
assert.equal(deployment.chainId, 31337);
assert.equal(new URL(deployment.rpcUrl).hostname, "127.0.0.1");
process.env.AUTOMATION_CONFIG = settings.AUTOMATION_CONFIG;
const { verifyDeployment } = await import("../runtime/src/deployment.js");
const { config, budget, stats } = await import("../runtime/src/chain.js");

assert.equal((await verifyDeployment()).status, "converged");
const factory = config.factory;
try {
	config.factory = config.sellToken;
	await assert.rejects(verifyDeployment(), {
		message: "executor_implementation_unverified",
	});
} finally {
	config.factory = factory;
}
const before = structuredClone(stats.methods);
const window = budget.windowId;
budget.take(budget.limit - budget.snapshot().used);
await assert.rejects(verifyDeployment(), {
	code: "observation_budget_exhausted",
});
assert.equal(budget.windowId, window, "proof crossed an RPC budget window");
assert.deepEqual(stats.methods, before);
assert.equal(stats.submissions, 0);
writeFileSync(
	".local/deployment-evidence.json",
	`${JSON.stringify(
		{
			manifestVersion: "moesi.manifest/v7",
			finalizedFactoryVerified: true,
			wrongCodeRejected: true,
			exhaustedBudgetRejectedBeforeDispatch: true,
			submissions: 0,
		},
		null,
		2,
	)}\n`,
);
console.log(
	"Published Moesi verifies the finalized factory; wrong code and exhausted budgets fail closed with zero submissions.",
);
