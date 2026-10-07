import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { GrantStoreAdapter } from "@oaath/sdk/advanced";
import {
	createPostgresOperationSchema,
	createPostgresOperationStoreAdapter,
} from "@oaath/server/postgres";
import { Pool } from "pg";
export const pool = new Pool({
	connectionString: process.env.DCA_DATABASE_URL,
	max: 8,
	connectionTimeoutMillis: 5000,
});
const secret = Buffer.from(process.env.DCA_SEAL_KEY ?? "", "hex");
if (secret.length !== 32) throw new Error("custody_key_required");
export const now = () => Math.floor(Date.now() / 1000);
export function seal(value: unknown, aad: string) {
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", secret, iv);
	cipher.setAAD(Buffer.from(aad));
	const data = Buffer.concat([
		cipher.update(JSON.stringify(value)),
		cipher.final(),
	]);
	return {
		version: "dca.sealed/v1",
		iv: iv.toString("hex"),
		data: data.toString("hex"),
		tag: cipher.getAuthTag().toString("hex"),
	};
}
export function open(value: any, aad: string): any {
	if (value?.version !== "dca.sealed/v1")
		throw new Error("custody_unavailable");
	try {
		const decipher = createDecipheriv(
			"aes-256-gcm",
			secret,
			Buffer.from(value.iv, "hex"),
		);
		decipher.setAAD(Buffer.from(aad));
		decipher.setAuthTag(Buffer.from(value.tag, "hex"));
		return JSON.parse(
			Buffer.concat([
				decipher.update(Buffer.from(value.data, "hex")),
				decipher.final(),
			]).toString(),
		);
	} catch {
		throw new Error("custody_unavailable");
	}
}
export async function getRecord(id: string, kind: string) {
	const r = await pool.query(
		"SELECT version,payload FROM dca_runtime_records WHERE plan_id=$1 AND kind=$2",
		[id, kind],
	);
	if (!r.rows[0]) return null;
	if (r.rows[0].version !== "dca.runtime/v1")
		throw new Error("runtime_version_unsupported");
	return open(r.rows[0].payload, `${id}:${kind}`);
}
export async function insertRecord(id: string, kind: string, value: unknown) {
	return (
		(
			await pool.query(
				"INSERT INTO dca_runtime_records(plan_id,kind,version,payload) VALUES($1,$2,'dca.runtime/v1',$3) ON CONFLICT DO NOTHING",
				[id, kind, seal(value, `${id}:${kind}`)],
			)
		).rowCount === 1
	);
}
export async function setRecord(id: string, kind: string, value: unknown) {
	await pool.query(
		"INSERT INTO dca_runtime_records(plan_id,kind,version,payload) VALUES($1,$2,'dca.runtime/v1',$3) ON CONFLICT(plan_id,kind) DO UPDATE SET payload=EXCLUDED.payload WHERE dca_runtime_records.version='dca.runtime/v1'",
		[id, kind, seal(value, `${id}:${kind}`)],
	);
}
export const grants: GrantStoreAdapter = {
	async get(id) {
		return (
			await pool.query("SELECT payload FROM dca_grants WHERE grant_id=$1", [id])
		).rows[0]?.payload;
	},
	async compareAndSwap({ grantId, expectedStoreRevision, next }) {
		const r =
			expectedStoreRevision === null
				? await pool.query(
						"INSERT INTO dca_grants(grant_id,revision,payload) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
						[grantId, next.storeRevision, next],
					)
				: await pool.query(
						"UPDATE dca_grants SET revision=$2,payload=$3 WHERE grant_id=$1 AND revision=$4",
						[grantId, next.storeRevision, next, expectedStoreRevision],
					);
		return r.rowCount === 1;
	},
	async close() {},
};
export const operations = createPostgresOperationStoreAdapter({ pool });
export async function init() {
	const c = await pool.connect();
	try {
		await c.query("BEGIN");
		await c.query("SELECT pg_advisory_xact_lock(74639201)");
		const exists = await c.query(
			"SELECT to_regclass('oaath_operation_lane_v2') AS name",
		);
		if (!exists.rows[0].name) await createPostgresOperationSchema(c);
		await c.query("COMMIT");
	} catch (e) {
		await c.query("ROLLBACK");
		throw e;
	} finally {
		c.release();
	}
}
export async function plan(id: string) {
	const p = (await pool.query("SELECT * FROM dca_plans WHERE id=$1", [id]))
		.rows[0];
	if (!p) throw new Error("plan_missing");
	return p;
}
