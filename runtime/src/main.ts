import { timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { activationWorker, approve, authorize, resume } from "./authority.js";
import { cancel, cancellationWorker } from "./cancel.js";
import { budget, stats } from "./chain.js";
import { init, pool } from "./store.js";
import { worker } from "./worker.js";

const token = process.env.DCA_RUNTIME_TOKEN;
if (!token) throw new Error("runtime_token_required");
await init();
const controller = new AbortController();
const server = createServer(async (req, res) => {
	try {
		const supplied = Buffer.from(req.headers.authorization ?? ""),
			expected = Buffer.from(`Bearer ${token}`);
		if (
			supplied.length !== expected.length ||
			!timingSafeEqual(supplied, expected)
		) {
			res.writeHead(401);
			res.end();
			return;
		}
		let size = 0;
		const chunks: Buffer[] = [];
		for await (const chunk of req) {
			size += chunk.length;
			if (size > 32768) throw new Error("request_too_large");
			chunks.push(chunk);
		}
		const body = JSON.parse(Buffer.concat(chunks).toString());
		if (req.method !== "POST" || !/^0x[0-9a-f]{64}$/.test(body.planId))
			throw new Error("request_invalid");
		let result: unknown;
		if (req.url === "/authorize") result = await authorize(body.planId);
		else if (req.url === "/approve")
			result = await approve(body.planId, body.input);
		else if (req.url === "/cancel") result = await cancel(body.planId);
		else if (req.url === "/resume") result = await resume(body.planId);
		else throw new Error("action_unavailable");
		res.writeHead(200, { "content-type": "application/json" });
		res.end(
			JSON.stringify(result, (_, v) =>
				typeof v === "bigint" ? v.toString() : v,
			),
		);
	} catch (e) {
		res.writeHead(409, { "content-type": "application/json" });
		res.end(
			JSON.stringify({
				error: {
					code:
						e instanceof Error && /^[a-z0-9_]{1,80}$/.test(e.message)
							? e.message
							: "runtime_action_unavailable",
				},
			}),
		);
	}
});
await new Promise<void>((resolve, reject) => {
	server.once("error", reject);
	server.listen(
		Number(process.env.DCA_RUNTIME_PORT ?? 4318),
		"127.0.0.1",
		resolve,
	);
});
const metrics = setInterval(
	() =>
		console.log(
			JSON.stringify({
				event: "rpc_method_counts",
				...stats,
				budget: budget.snapshot(),
			}),
		),
	60000,
);
metrics.unref();
const loops = [
	...Array.from({ length: 4 }, () => worker(controller.signal)),
	cancellationWorker(controller.signal),
	activationWorker(controller.signal),
].map((p) =>
	p.catch(() => {
		console.error("worker_stopped");
		controller.abort();
	}),
);
process.on("SIGTERM", () => controller.abort());
process.on("SIGINT", () => controller.abort());
await Promise.all(loops);
clearInterval(metrics);
await new Promise<void>((r) => server.close(() => r()));
await pool.end();
