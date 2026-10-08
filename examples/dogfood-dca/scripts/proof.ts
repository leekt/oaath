import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { dca, input, owner, until } from "./proof-support.js";

try {
	const request = input("purchase", 15),
		p = await dca.create(request);
	assert.equal((await dca.create(request)).id, p.id);
	assert.equal((await dca.authorize(p.id)).status, "active");
	await until(async () => {
		await owner("mine");
		return (await dca.listRuns(p.id)).runs[0]?.status === "succeeded";
	}, 50);
	writeFileSync(".local/proof-plan.json", JSON.stringify({ id: p.id }));
	console.log(
		"Packed public SDK completed a real Kernel v4 and Uniswap v3 purchase",
	);
} catch (e) {
	console.error(
		"Purchase proof failed",
		e instanceof Error ? e.message : "unknown",
	);
	process.exitCode = 1;
}
