import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { createAutomation } from "../.local/consumer/node_modules/@oaath/automation/dist/index.js";
import { createAutomationServer } from "../.local/consumer/node_modules/@oaath/automation/dist/server.js";
import { config, env, input, owner, until } from "./proof-support.js";

const backend = createAutomationServer({
	baseUrl: "http://127.0.0.1:4317",
	token: env.AUTOMATION_API_TOKEN,
});
try {
	await backend.configureSigning({ keyScope: "application" });
	const clients = await Promise.all(
		["shared-a", "shared-b"].map(async (userId) =>
			createAutomation({
				baseUrl: "http://127.0.0.1:4317",
				token: (
					await backend.createSession({ userId, account: config.account })
				).token,
			}),
		),
	);
	const plans = await Promise.all(
		clients.map((client, i) =>
			client.create({ ...input(`shared-${i}`, 35), opportunities: 1 }),
		),
	);
	const reviews = await Promise.all(
		clients.map((client, i) => client.authorize(plans[i]!.id)),
	);
	assert.equal(reviews[0]!.plan.signer, reviews[1]!.plan.signer);
	assert.notEqual(reviews[0]!.plan.executor, reviews[1]!.plan.executor);
	assert.notEqual(
		reviews[0]!.review!.commitment,
		reviews[1]!.review!.commitment,
	);
	for (let i = 0; i < 2; i++) {
		const r = reviews[i]!.review!;
		assert.equal(r.keyScope, "application");
		const consentSignature = (await owner("sign", r.consent)).signature;
		const permissionSignature = (await owner("sign", r.permission)).signature;
		await owner("calls", { calls: r.setupCalls });
		await owner("mine");
		assert.equal(
			(
				await clients[i]!.submitApproval(plans[i]!.id, {
					commitment: r.commitment,
					consentSignature,
					permissionSignature,
				})
			).status,
			"active",
		);
	}
	await assert.rejects(clients[0]!.get(plans[1]!.id));
	const cancelling = await clients[0]!.cancel(plans[0]!.id);
	assert.ok(cancelling.cancellation?.calls?.length);
	await owner("calls", { calls: cancelling.cancellation!.calls });
	await owner("mine");
	assert.equal((await clients[0]!.cancel(plans[0]!.id)).status, "cancelled");
	assert.equal((await clients[1]!.get(plans[1]!.id)).status, "active");
	await until(async () => {
		await owner("mine");
		return (
			(await clients[1]!.listRuns(plans[1]!.id)).runs[0]?.status === "succeeded"
		);
	}, 70);
	assert.equal(
		(await clients[1]!.get(plans[1]!.id)).signer,
		reviews[0]!.plan.signer,
	);
	const cleanup = await clients[1]!.cancel(plans[1]!.id);
	await owner("calls", { calls: cleanup.cancellation!.calls });
	await owner("mine");
	assert.equal((await clients[1]!.cancel(plans[1]!.id)).status, "cancelled");
	console.log(
		"Two users shared one app key with separate consent and executors; cancelling one preserved the other's successful purchase.",
	);
	writeFileSync(
		".local/shared-key-evidence.json",
		JSON.stringify(
			{
				sameSigner: true,
				separateConsent: true,
				separateExecutors: true,
				crossUserDenied: true,
				cancelOnePreservesOther: true,
				otherPurchaseFinalized: true,
			},
			null,
			2,
		),
	);
} finally {
	await backend.configureSigning({ keyScope: "user" });
}
