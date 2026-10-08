import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
export const env = JSON.parse(readFileSync(".local/environment.json", "utf8"));
export const config = JSON.parse(readFileSync(env.AUTOMATION_CONFIG, "utf8"));
const publicSdk = (await import(
	new URL(
		"../.local/consumer/node_modules/@oaath/automation/dist/index.js",
		import.meta.url,
	).href
)) as typeof import("../sdk/src/index.js");
const approvalSdk = (await import(
	new URL(
		"../.local/consumer/node_modules/@oaath/automation/dist/approval.js",
		import.meta.url,
	).href
)) as typeof import("../sdk/src/approval.js");
export async function owner(action: string, body: unknown = {}) {
	const r = await fetch(`http://127.0.0.1:4319/${action}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${env.DCA_OWNER_TOKEN}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
	if (!r.ok) throw Error(`owner_${action}_failed`);
	return r.json();
}
const db = new DatabaseSync(".local/owner-consent.sqlite");
db.exec(
	"PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS approvals(key TEXT PRIMARY KEY, record TEXT NOT NULL)",
);
const sessionResponse = await fetch("http://127.0.0.1:4317/v1/sessions", {
	method: "POST",
	headers: {
		authorization: `Bearer ${env.AUTOMATION_API_TOKEN}`,
		"content-type": "application/json",
	},
	body: JSON.stringify({ userId: "proof-user", account: config.account }),
});
if (!sessionResponse.ok) throw Error("session_failed");
export const session = await sessionResponse.json();
const client = publicSdk.createAutomation({
	baseUrl: "http://127.0.0.1:4317",
	token: session.token,
});
const approval = approvalSdk.createOwnerApproval({
	journal: {
		read: async (key) => {
			const r = db
				.prepare("SELECT record FROM approvals WHERE key=?")
				.get(key) as { record: string } | undefined;
			return r ? JSON.parse(r.record as string) : null;
		},
		compareAndSwap: async (key, expected, next) => {
			const r =
				expected === null
					? db
							.prepare(
								"INSERT OR IGNORE INTO approvals(key,record) VALUES(?,?)",
							)
							.run(key, JSON.stringify(next))
					: db
							.prepare("UPDATE approvals SET record=? WHERE key=? AND record=?")
							.run(JSON.stringify(next), key, JSON.stringify(expected));
			return Number(r.changes) === 1;
		},
	},
	confirm: async (review) => {
		console.log(
			"Owner reviewed exact onchain terms",
			JSON.stringify({
				terms: review.terms,
				fees: review.fees,
				custody: review.custody,
				setupTargets: review.setupCalls.map((c) => c.target),
			}),
		);
		return true;
	},
	signTypedData: async (input) => (await owner("sign", input)).signature,
	executeSetup: async (calls) => {
		const result = await owner("calls", { calls });
		if (result.outcome.status !== "finalized") throw Error("setup_pending");
		await owner("mine");
		return { operationId: result.operationId };
	},
});
export const dca = Object.freeze({
	...client,
	async authorize(id: string) {
		const a = await client.authorize(id);
		return a.review ? client.submitApproval(id, await approval(a.review)) : a;
	},
});
export function input(name: string, startIn = 12) {
	return {
		recipe: "dca.v1" as const,
		amount: "25",
		opportunities: 30,
		maxSlippageBps: 50,
		startAt: Math.floor(Date.now() / 1000) + startIn,
		idempotencyKey: `${name}-${Date.now()}`,
	};
}
export const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
export async function until(fn: () => Promise<boolean>, seconds = 90) {
	const end = Date.now() + seconds * 1000;
	while (Date.now() < end) {
		if (await fn()) return;
		await wait(1000);
	}
	throw Error("proof_timeout");
}
