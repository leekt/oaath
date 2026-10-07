import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { recoverAddress } from "cetane/utils";
import { Pool } from "pg";

const env = JSON.parse(readFileSync(".local/environment.json", "utf8"));
const pool = new Pool({ connectionString: env.AUTOMATION_DATABASE_URL });
const app = `signer-proof-${randomBytes(8).toString("hex")}`;
function processCall(input: unknown): Promise<any> {
	return new Promise((resolve, reject) => {
		const c = spawn(process.execPath, ["scripts/signer-process.ts"], {
			stdio: ["pipe", "pipe", "ignore"],
		});
		let out = "";
		c.stdout.on("data", (d) => (out += d));
		c.on("exit", (code) => {
			try {
				if (code !== 0) throw Error();
				resolve(JSON.parse(out));
			} catch {
				reject(Error("signer_child_failed"));
			}
		});
		c.stdin.end(JSON.stringify(input));
	});
}
try {
	const identity = { applicationId: app, scope: "application" };
	const [a, b] = await Promise.all([
		processCall({ action: "create", identity }),
		processCall({ action: "create", identity }),
	]);
	assert.ok(a.ok && b.ok);
	assert.deepEqual(a.result, b.result);
	const retained = await processCall({
		action: "recover",
		identity,
		address: a.result.address,
	});
	assert.deepEqual(retained, a);
	const users = await Promise.all(
		["a", "b"].map((userId) =>
			processCall({
				action: "create",
				identity: { applicationId: app, scope: "user", userId },
			}),
		),
	);
	assert.notEqual(users[0].result.address, users[1].result.address);
	assert.notEqual(users[0].result.address, a.result.address);
	const other = await processCall({
		action: "create",
		identity: { ...identity, applicationId: app + "-other" },
	});
	assert.notEqual(other.result.address, a.result.address);
	const hash = `0x${"ab".repeat(32)}` as const;
	const signed = await processCall({
		action: "sign",
		identity,
		address: a.result.address,
		hash,
	});
	assert.equal(
		recoverAddress({ hash, signature: signed.result }).toLowerCase(),
		a.result.address,
	);
	const row = (
		await pool.query(
			"DELETE FROM oaath_signer_binding_v1 WHERE id=$1 RETURNING *",
			[a.result.bindingId],
		)
	).rows[0];
	assert.equal(
		(
			await processCall({
				action: "recover",
				identity,
				address: a.result.address,
			})
		).code,
		"signer_custody_missing",
	);
	assert.equal(
		(
			await pool.query(
				"SELECT count(*) FROM oaath_signer_binding_v1 WHERE id=$1",
				[row.id],
			)
		).rows[0].count,
		"0",
	);
	await pool.query(
		"INSERT INTO oaath_signer_binding_v1(id,version,payload) VALUES($1,$2,$3)",
		[row.id, row.version, row.payload],
	);
	console.log(
		"Independent OS processes: one shared credential, per-user and app isolation, exact signature recovery, missing custody never rotated.",
	);
	writeFileSync(
		".local/signer-evidence.json",
		JSON.stringify(
			{
				independentProcesses: true,
				concurrentCreateOneCredential: true,
				perUserDistinct: true,
				tenantIsolation: true,
				exactDigestSignature: true,
				missingCustodyNeverRotates: true,
			},
			null,
			2,
		),
	);
} finally {
	await pool.end();
}
