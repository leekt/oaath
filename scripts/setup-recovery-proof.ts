import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dca, env, input, owner, until, wait } from "./proof-support.js";

try {
	const p = await dca.create(input("pending-setup", 20));
	const response = await fetch(
		`http://127.0.0.1:4317/v1/plans/${p.id}/authorize`,
		{
			method: "POST",
			headers: { authorization: `Bearer ${env.DCA_API_TOKEN}` },
		},
	);
	assert.equal(response.status, 200);
	const { review } = await response.json();
	console.log(
		"Owner reviewed pending setup",
		JSON.stringify({
			terms: review.terms,
			fees: review.fees,
			custody: review.custody,
		}),
	);
	const consent = await owner("sign", review.consent),
		permission = await owner("sign", review.permission);
	const pending = await dca.submitApproval(p.id, {
		commitment: review.commitment,
		consentSignature: consent.signature,
		permissionSignature: permission.signature,
	});
	assert.equal(pending.status, "pending");
	assert.equal(pending.plan.status, "awaiting_consent");
	for (const mode of ["runtime", "api"])
		execFileSync(process.execPath, ["scripts/stop.mjs", mode]);
	const setup = await owner("calls", { calls: review.setupCalls });
	assert.equal(setup.outcome.status, "finalized");
	await owner("mine");
	for (const mode of ["api", "runtime"]) {
		const child = spawn(
			mode === "api" ? "./target/release/dca-api" : process.execPath,
			mode === "api" ? [] : ["runtime/src/main.ts"],
			{ env: { ...process.env, ...env }, stdio: "ignore", detached: true },
		);
		writeFileSync(`.local/${mode}.pid`, String(child.pid));
		child.unref();
		if (mode === "api") await wait(1000);
	}
	await until(async () => {
		await owner("mine");
		return (await dca.get(p.id)).status === "active";
	}, 90);
	const active = await dca.get(p.id);
	assert.equal(active.signer, pending.plan.signer);
	assert.equal(active.commitment, review.commitment);
	await until(async () => {
		await owner("mine");
		return (await dca.listRuns(p.id)).runs[0]?.status === "succeeded";
	}, 50);
	writeFileSync(".local/proof-plan.json", JSON.stringify({ id: p.id }));
	writeFileSync(
		".local/setup-recovery-evidence.json",
		JSON.stringify(
			{
				planId: p.id,
				apiRecreated: true,
				executionServiceRecreated: true,
				activatedWithoutClientResubmission: true,
				sameSigner: true,
				successfulPurchase: true,
			},
			null,
			2,
		),
	);
	console.log(
		"Recreated Rust API and execution service activated retained consent and finalized purchase without client resubmission",
	);
} catch (e) {
	console.error(
		"Setup recovery failed",
		e instanceof Error ? e.message : "unknown",
	);
	process.exitCode = 1;
}
