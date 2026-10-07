/** Owned local example only. The product API remains Rust; owner fixture credentials never enter the browser. */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createAutomation } from "@oaath/automation";
import { createOwnerApproval } from "@oaath/automation/approval";
import { createOwnerCancellation } from "@oaath/automation/cancellation";
import { createAutomationServer } from "@oaath/automation/server";

const root = resolve(import.meta.dir, "../..");
const env = JSON.parse(readFileSync(`${root}/.local/environment.json`, "utf8"));
const config = JSON.parse(readFileSync(env.AUTOMATION_CONFIG, "utf8"));
const publicConfig = JSON.parse(
	readFileSync(`${root}/.local/public-url.json`, "utf8"),
);
const origin = publicConfig.webUrl;
if (!origin || config.chainId !== 31337) throw Error("local_fixture_required");
const allowedHosts = new Set([new URL(origin).host, "127.0.0.1:4320"]);
const backend = createAutomationServer({
	baseUrl: "http://127.0.0.1:4317",
	token: env.AUTOMATION_API_TOKEN,
});
const db = new DatabaseSync(`${root}/.local/example-owner.sqlite`);
db.exec(
	"PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS actions(key TEXT PRIMARY KEY,record TEXT NOT NULL)",
);
const journal = {
	async read(key: string) {
		const r = db.prepare("SELECT record FROM actions WHERE key=?").get(key) as
			| { record: string }
			| undefined;
		return r ? JSON.parse(r.record) : null;
	},
	async compareAndSwap(key: string, expected: unknown, next: unknown) {
		const result =
			expected === null
				? db
						.prepare("INSERT OR IGNORE INTO actions(key,record) VALUES(?,?)")
						.run(key, JSON.stringify(next))
				: db
						.prepare("UPDATE actions SET record=? WHERE key=? AND record=?")
						.run(JSON.stringify(next), key, JSON.stringify(expected));
		return Number(result.changes) === 1;
	},
};
async function fixture(action: string, body: unknown = {}) {
	const r = await fetch(`http://127.0.0.1:4319/${action}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${env.DCA_OWNER_TOKEN}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
		signal: AbortSignal.timeout(45000),
	});
	if (!r.ok) throw Error("fixture_action_pending");
	return r.json();
}
const approve = createOwnerApproval({
	journal,
	confirm: async () => true,
	signTypedData: async (data) => (await fixture("sign", data)).signature,
	executeSetup: async (calls) => {
		const r = await fixture("calls", { calls });
		await fixture("mine");
		return { operationId: r.operationId };
	},
});
const cancel = createOwnerCancellation({
	journal,
	executeCalls: async (calls) => {
		const r = await fixture("calls", { calls });
		await fixture("mine");
		return { operationId: r.operationId };
	},
});
const digest = (id: string) =>
	createHmac("sha256", env.AUTOMATION_API_TOKEN).update(id).digest("hex");
function customer(req: Request) {
	const raw = req.headers
		.get("cookie")
		?.match(/(?:^|;\s*)automation_demo=([a-f0-9.]+)/)?.[1];
	if (raw) {
		const [id, sig] = raw.split(".");
		if (
			id?.length === 32 &&
			sig?.length === 64 &&
			timingSafeEqual(Buffer.from(sig), Buffer.from(digest(id)))
		)
			return id;
	}
	return randomBytes(16).toString("hex");
}
const files = new Map([
	["/", "index.html"],
	["/app.js", "app.js"],
	["/automation.css", "automation.css"],
]);
const server = Bun.serve({
	hostname: "127.0.0.1",
	port: 4320,
	idleTimeout: 60,
	async fetch(req) {
		const url = new URL(req.url);
		const headers = new Headers({
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
			"content-security-policy":
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
		});
		const json = (value: unknown, status = 200) => {
			headers.set("content-type", "application/json");
			return new Response(JSON.stringify(value), { status, headers });
		};
		try {
			if (!allowedHosts.has(req.headers.get("host") ?? ""))
				return json({ error: "host_denied" }, 421);
			if (req.headers.has("origin") && req.headers.get("origin") !== origin)
				return json({ error: "origin_denied" }, 403);
			if (req.method === "POST" && url.pathname === "/api/session") {
				const id = customer(req);
				headers.set(
					"set-cookie",
					`automation_demo=${id}.${digest(id)}; HttpOnly; SameSite=Strict; Path=/; ${origin.startsWith("https:") ? "Secure; " : ""}Max-Age=86400`,
				);
				return json(
					await backend.createSession({
						userId: `demo-${id}`,
						account: config.account,
					}),
				);
			}
			if (url.pathname.startsWith("/api/automation/v1/")) {
				const path = url.pathname.slice("/api/automation".length) + url.search;
				const r = await fetch(`http://127.0.0.1:4317${path}`, {
					method: req.method,
					headers: {
						authorization: req.headers.get("authorization") ?? "",
						"content-type": "application/json",
					},
					body: req.method === "GET" ? undefined : await req.text(),
					redirect: "error",
					signal: AbortSignal.timeout(35000),
				});
				headers.set(
					"content-type",
					r.headers.get("content-type") ?? "application/json",
				);
				return new Response(r.body, { status: r.status, headers });
			}
			if (
				req.method === "POST" &&
				["/demo/approve", "/demo/cancel"].includes(url.pathname)
			) {
				const text = await req.text();
				if (text.length > 2048) return json({ error: "body_too_large" }, 413);
				const body = JSON.parse(text);
				const token =
					req.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
				const client = createAutomation({
					baseUrl: "http://127.0.0.1:4317",
					token,
				});
				const plan = await client.get(body.planId);
				if (
					plan.terms.account !== config.account ||
					plan.terms.chainId !== 31337
				)
					throw Error("local_plan_required");
				if (url.pathname === "/demo/cancel") return json(await cancel(plan));
				const authorization = await client.authorize(plan.id);
				const review = authorization.review;
				if (!review || review.commitment !== body.commitment)
					throw Error("review_mismatch");
				return json(await approve(review));
			}
			const file = files.get(url.pathname);
			if (req.method === "GET" && file) {
				headers.set(
					"content-type",
					file.endsWith("html")
						? "text/html; charset=utf-8"
						: file.endsWith("css")
							? "text/css"
							: "application/javascript",
				);
				return new Response(Bun.file(resolve(import.meta.dir, "dist", file)), {
					headers,
				});
			}
			return json({ error: "not_found" }, 404);
		} catch {
			return json({ error: "demo_action_pending_or_rejected" }, 409);
		}
	},
});
console.log(`DCA example ready: ${origin}`);
process.on("SIGTERM", () => {
	server.stop();
	db.close();
	process.exit();
});
