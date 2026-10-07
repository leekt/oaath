import assert from "node:assert/strict";
import { Pool } from "pg";
import { dca, env, input, owner } from "./proof-support.js";

const pool = new Pool({
	connectionString: env.AUTOMATION_DATABASE_URL,
	max: 2,
});
const raw = async (path: string, body?: unknown) =>
	fetch(`http://127.0.0.1:4317/v1/plans/${path}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${env.AUTOMATION_API_TOKEN}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body ?? {}),
	});
try {
	const p = await dca.create(input("negative", 300));
	await assert.rejects(dca.resume(p.id));
	await assert.rejects(dca.submitApproval(p.id, {}));
	assert.equal((await dca.get(p.id)).status, "draft");
	const reviews = await Promise.all([
		raw(`${p.id}/authorize`).then((r) => r.json()),
		raw(`${p.id}/authorize`).then((r) => r.json()),
	]);
	assert.equal(reviews[0].review.commitment, reviews[1].review.commitment);
	assert.equal(reviews[0].plan.signer, reviews[1].plan.signer);
	const r = reviews[0].review;
	await assert.rejects(
		dca.submitApproval(p.id, { commitment: `0x${"00".repeat(32)}` }),
	);
	const session = (
		await pool.query(
			"DELETE FROM automation_runtime_records WHERE plan_id=$1 AND kind='session' RETURNING *",
			[p.id],
		)
	).rows[0];
	assert.equal((await raw(`${p.id}/authorize`)).status, 409);
	assert.equal(
		(
			await pool.query(
				"SELECT count(*) FROM automation_runtime_records WHERE plan_id=$1 AND kind='session'",
				[p.id],
			)
		).rows[0].count,
		"0",
	);
	await pool.query(
		"INSERT INTO automation_runtime_records(plan_id,kind,version,payload) VALUES($1,$2,$3,$4)",
		[p.id, session.kind, session.version, session.payload],
	);
	const consent = await owner("sign", r.consent),
		permission = await owner("sign", r.permission);
	await pool.query(
		"UPDATE automation_plans SET terms=jsonb_set(terms,'{maxSlippageBps}','51') WHERE id=$1",
		[p.id],
	);
	await assert.rejects(
		dca.submitApproval(p.id, {
			commitment: r.commitment,
			consentSignature: consent.signature,
			permissionSignature: permission.signature,
		}),
	);
	await pool.query(
		"UPDATE automation_plans SET terms=jsonb_set(terms,'{maxSlippageBps}','50') WHERE id=$1",
		[p.id],
	);
	assert.equal((await dca.get(p.id)).status, "awaiting_consent");
	const pending = await dca.cancel(p.id);
	assert.equal(pending.status, "cancelling");
	const calls = (pending.cancellation as any)?.calls;
	assert.ok(calls?.length);
	await owner("calls", { calls });
	await owner("mine");
	assert.equal((await dca.cancel(p.id)).status, "cancelled");
	await assert.rejects(dca.resume(p.id));
	console.log(
		"Absent consent, changed terms, concurrent review, missing custody, pre-activation cancellation and forbidden reactivation passed",
	);
} catch (e) {
	console.error(
		"Negative proof failed",
		e instanceof Error ? e.message : "unknown",
	);
	process.exitCode = 1;
} finally {
	await pool.end();
}
