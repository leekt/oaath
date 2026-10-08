import assert from "node:assert/strict";
import { type ChildProcess, spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
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

const children: ChildProcess[] = [];
const pool = new Pool({
	connectionString: env.AUTOMATION_DATABASE_URL,
	max: 2,
});
let armed = false,
	intercepted = false,
	submissions = 0,
	victim: ChildProcess | undefined;
const upstream = config.chainDescriptors[31337].bundlerUrl;
const proxy = createServer(async (req, res) => {
	const buffers = [];
	for await (const b of req) buffers.push(b);
	const body = Buffer.concat(buffers);
	const method = JSON.parse(body.toString()).method;
	const response = await fetch(upstream, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body,
	});
	const reply = await response.text();
	if (method === "eth_sendUserOperation") {
		submissions++;
		if (armed) {
			armed = false;
			intercepted = true;
			victim?.kill("SIGKILL");
			return;
		}
	}
	res.writeHead(response.status, { "content-type": "application/json" });
	res.end(reply);
});
await new Promise<void>((r) => proxy.listen(4330, "127.0.0.1", r));
const faultConfig = structuredClone(config);
faultConfig.chainDescriptors[31337].bundlerUrl = "http://127.0.0.1:4330";
writeFileSync(".local/recovery-config.json", JSON.stringify(faultConfig), {
	mode: 0o600,
});
function start(port: number) {
	const child = spawn(process.execPath, ["runtime/src/main.ts"], {
		env: {
			...process.env,
			...env,
			AUTOMATION_CONFIG: new URL(
				"../.local/recovery-config.json",
				import.meta.url,
			).pathname,
			AUTOMATION_RUNTIME_PORT: String(port),
		},
		stdio: ["ignore", "ignore", "pipe"],
	});
	child.stderr?.on("data", () => {});
	children.push(child);
	return child;
}
try {
	victim = start(4318);
	await wait(1500);
	const p = await dca.create(input("lost-reply", 16));
	const auth = await dca.authorize(p.id);
	assert.equal(auth.status, "active");
	const saved = await dca.get(p.id);
	const before = (await owner("stats")).submissions;
	armed = true;
	await until(async () => {
		await owner("mine");
		return intercepted;
	}, 40);
	assert.equal(submissions, 1);
	console.log(
		"Killed execution process after bundler accepted purchase, before acknowledgement",
	);
	const pointer = (
		await pool.query("SELECT operation FROM automation_runs WHERE plan_id=$1", [
			p.id,
		])
	).rows[0].operation;
	assert.ok(pointer.identity.userOperationHash);
	// Independent processes, fresh pools and the existing caller key. Neither can replace this intent.
	start(4318);
	start(4321);
	await until(async () => {
		await owner("mine");
		return (await dca.listRuns(p.id)).runs[0]?.status === "succeeded";
	}, 100);
	assert.equal(submissions, 1);
	assert.equal((await owner("stats")).submissions, before + 1);
	const after = await dca.get(p.id);
	assert.equal(after.signer, saved.signer);
	assert.equal(after.commitment, saved.commitment);
	const finalPointer = (
		await pool.query("SELECT operation FROM automation_runs WHERE plan_id=$1", [
			p.id,
		])
	).rows[0].operation;
	assert.deepEqual(finalPointer, pointer);
	console.log(
		"Two recreated processes recovered one exact core identity; zero replacement submissions",
	);
	const statsBefore = await owner("stats");
	for (let i = 0; i < 20; i++) {
		await dca.get(p.id);
		await dca.listRuns(p.id);
	}
	const statsAfter = await owner("stats");
	assert.equal(statsAfter.rpc, statsBefore.rpc);
	console.log("40 status/history reads generated zero chain RPC methods");
	writeFileSync(".local/proof-plan.json", JSON.stringify({ id: p.id }));
	writeFileSync(
		".local/recovery-evidence.json",
		JSON.stringify(
			{
				planId: p.id,
				operation: pointer.identity.userOperationHash,
				submissions,
				replacementSubmissions: 0,
				statusRequests: 40,
				statusRpcDelta: statsAfter.rpc - statsBefore.rpc,
				signerRecovered: after.signer === saved.signer,
			},
			null,
			2,
		),
	);
} catch (e) {
	console.error(
		"Recovery proof failed",
		e instanceof Error ? e.message : "unknown",
	);
	process.exitCode = 1;
} finally {
	for (const c of children) if (c.exitCode === null) c.kill("SIGTERM");
	await wait(1500);
	for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
	proxy.closeAllConnections();
	proxy.close();
	await pool.end();
}
