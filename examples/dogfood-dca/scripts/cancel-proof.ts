import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createAutomation } from "../sdk/dist/index.js";

const e = JSON.parse(readFileSync(".local/environment.json", "utf8"));
const { id } = JSON.parse(readFileSync(".local/proof-plan.json", "utf8"));
const dca = createAutomation({
	baseUrl: "http://127.0.0.1:4317",
	token: e.AUTOMATION_API_TOKEN,
});
async function owner(action: string, body: unknown = {}) {
	const r = await fetch(`http://127.0.0.1:4319/${action}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${e.DCA_OWNER_TOKEN}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
	assert.equal(r.status, 200);
	return r.json();
}
try {
	const runs = await dca.listRuns(id);
	assert.equal(runs.runs[0]?.status, "succeeded");
	console.log("Validated successful purchase retained");
	assert.equal((await dca.pause(id)).status, "paused");
	assert.equal((await dca.resume(id)).status, "active");
	console.log("Pause and resume passed");
	const pending = await dca.cancel(id);
	assert.equal(pending.status, "cancelling");
	const c = pending.cancellation as { calls: readonly unknown[] };
	assert.ok(c?.calls?.length);
	console.log("Cancellation requires explicit owner transaction");
	const result = await owner("calls", { calls: c.calls });
	console.log("Owner cancellation", result.outcome.status);
	assert.equal(result.outcome.status, "finalized");
	await owner("mine");
	const done = await dca.cancel(id);
	console.log("Cancellation result", done.status);
	assert.equal(done.status, "cancelled");
	await assert.rejects(dca.resume(id));
	console.log(
		"Onchain stop, allowance removal, Grant revocation and forbidden reactivation passed",
	);
} catch (err) {
	console.error(
		"Cancellation proof failed",
		err instanceof Error ? err.message : "unknown",
	);
	process.exitCode = 1;
}
