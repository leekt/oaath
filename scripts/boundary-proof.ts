import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { Pool } from "pg";
import {
	config,
	dca,
	env,
	input,
	owner,
	until,
	wait,
} from "./proof-support.js";

const pool = new Pool({
		connectionString: env.AUTOMATION_DATABASE_URL,
		max: 2,
	}),
	children: ChildProcess[] = [];
let finalityBlock: any;
const proxy = createServer(async (req, res) => {
	const chunks = [];
	for await (const b of req) chunks.push(b);
	const body = Buffer.concat(chunks);
	const request = JSON.parse(body.toString());
	if (
		request.method === "eth_getBlockByNumber" &&
		request.params[0] === "finalized" &&
		finalityBlock
	) {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(
			JSON.stringify({ jsonrpc: "2.0", id: request.id, result: finalityBlock }),
		);
		return;
	}
	const response = await fetch(config.rpcUrl, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body,
	});
	res.writeHead(response.status, { "content-type": "application/json" });
	res.end(await response.text());
});
await new Promise<void>((r) => proxy.listen(4322, "127.0.0.1", r));
const faultConfig = structuredClone(config);
faultConfig.chainDescriptors[31337].publicRpcUrls = ["http://127.0.0.1:4322"];
writeFileSync(".local/boundary-config.json", JSON.stringify(faultConfig));
for (const p of ["reservation", "publication", "inclusion"]) {
	if (existsSync(`.local/fault-${p}.json`))
		unlinkSync(`.local/fault-${p}.json`);
}
try {
	const plans: { point: string; id: string }[] = [];
	for (const point of ["reservation", "publication", "inclusion"]) {
		const p = await dca.create(input(point, 18));
		assert.equal((await dca.authorize(p.id)).status, "active");
		plans.push({ point, id: p.id });
	}
	execFileSync(process.execPath, ["scripts/stop.mjs", "runtime"]);
	const before = (await owner("stats")).submissions;
	finalityBlock = (
		await (
			await fetch(config.rpcUrl, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					jsonrpc: "2.0",
					id: 1,
					method: "eth_getBlockByNumber",
					params: ["finalized", false],
				}),
			})
		).json()
	).result;
	for (const p of plans) {
		const c = spawn(process.execPath, ["scripts/fault-worker.ts"], {
			env: {
				...process.env,
				...env,
				AUTOMATION_CONFIG: new URL(
					"../.local/boundary-config.json",
					import.meta.url,
				).pathname,
				FAULT_PLAN: p.id,
				FAULT_POINT: p.point,
			},
			stdio: ["ignore", "ignore", "pipe"],
		});
		children.push(c);
		c.stderr?.on("data", () => {});
	}
	await until(async () => {
		await owner("mine");
		return plans.every((p) => existsSync(`.local/fault-${p.point}.json`));
	}, 50);
	console.log(
		"Actual processes killed after reservation, after core publication, and after inclusion",
	);
	const retained = await pool.query(
		"SELECT plan_id,operation FROM automation_runs WHERE plan_id=ANY($1)",
		[plans.map((p) => p.id)],
	);
	assert.equal(retained.rowCount, 3);
	for (const r of retained.rows) assert.ok(r.operation?.identity);
	const service = spawn(process.execPath, ["runtime/src/main.ts"], {
		env: { ...process.env, ...env },
		stdio: "ignore",
	});
	children.push(service);
	writeFileSync(".local/runtime.pid", String(service.pid));
	await until(async () => {
		await owner("mine");
		const runs = await Promise.all(plans.map((p) => dca.listRuns(p.id)));
		return (
			runs[0]?.runs[0]?.status === "unresolved" &&
			runs[1]?.runs[0]?.status === "unresolved" &&
			runs[2]?.runs[0]?.status === "succeeded"
		);
	}, 100);
	assert.equal((await owner("stats")).submissions, before + 1);
	const after = await pool.query(
		"SELECT plan_id,operation FROM automation_runs WHERE plan_id=ANY($1) ORDER BY plan_id",
		[plans.map((p) => p.id)],
	);
	assert.deepEqual(
		after.rows,
		retained.rows.sort((a, b) => a.plan_id.localeCompare(b.plan_id)),
	);
	for (const p of plans) {
		await dca.pause(p.id);
		const state = await dca.get(p.id);
		assert.equal(state.status, "paused");
	}
	writeFileSync(
		".local/boundary-evidence.json",
		JSON.stringify(
			{
				points: plans.map((p) => p.point),
				processRecreation: true,
				submissions: 1,
				replacements: 0,
				missingAndPreparedRemainUnresolved: true,
			},
			null,
			2,
		),
	);
	console.log(
		"Recovery preserved all identities; missing/prepared records stayed unresolved; included swap finalized with no new send",
	);
} catch (e) {
	console.error(
		"Boundary proof failed",
		e instanceof Error ? e.message : "unknown",
	);
	process.exitCode = 1;
} finally {
	for (const c of children) if (c.exitCode === null) c.kill("SIGTERM");
	await wait(1200);
	for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
	proxy.closeAllConnections();
	proxy.close();
	await pool.end();
}
