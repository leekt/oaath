/** Example application backend. The Automation product API is the Rust service. */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAutomationServer } from "@oaath/automation/server";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import {
	createKernelRuntime,
	kernelDeployment,
	kernelKey,
	ownerOperator,
} from "@oaath/sdk/kernel";
import type { Address, Hex } from "cetane";
import { hashMessage, recoverAddress } from "cetane/utils";
import { Pool } from "pg";
import {
	address,
	apiPath,
	CHAIN_ID,
	loginMessage,
	ORIGIN,
	rpcAllowed,
} from "./policy.js";

const config = JSON.parse(readFileSync(process.env.AUTOMATION_CONFIG!, "utf8"));
if (config.chainId !== CHAIN_ID || config.origin !== ORIGIN)
	throw Error("hosting_profile_invalid");
const pool = new Pool({
	connectionString: process.env.AUTOMATION_DATABASE_URL,
	max: 4,
});
const backend = createAutomationServer({
	baseUrl: "http://127.0.0.1:4317",
	token: process.env.AUTOMATION_API_TOKEN!,
});
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
const now = () => Math.floor(Date.now() / 1000);
await pool.query(`
 CREATE TABLE IF NOT EXISTS dca_login_challenges(nonce text PRIMARY KEY,owner text NOT NULL,expires bigint NOT NULL);
 CREATE TABLE IF NOT EXISTS dca_wallet_sessions(digest text PRIMARY KEY,owner text NOT NULL,account text NOT NULL,deployment jsonb NOT NULL,api_token text NOT NULL,expires bigint NOT NULL);
 CREATE TABLE IF NOT EXISTS dca_gateway_budgets(window_id bigint NOT NULL,scope text NOT NULL,used integer NOT NULL,PRIMARY KEY(window_id,scope));
`);
async function admit(scope: string, limit: number) {
	const r = await pool.query(
		`INSERT INTO dca_gateway_budgets(window_id,scope,used) VALUES($1,$2,1)
 ON CONFLICT(window_id,scope) DO UPDATE SET used=dca_gateway_budgets.used+1 WHERE dca_gateway_budgets.used<$3 RETURNING used`,
		[Math.floor(now() / 600), scope, limit],
	);
	if (!r.rowCount) throw Error("request_budget_exhausted");
}
async function rpc(method: string, params: unknown[] = [], bundler = false) {
	await admit("rpc", 3000);
	const response = await fetch(
		bundler ? config.chainDescriptors[CHAIN_ID].bundlerUrl : config.rpcUrl,
		{
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
			signal: AbortSignal.timeout(12000),
			redirect: "error",
		},
	);
	const value = (await response.json()) as any;
	if (!response.ok || value.error || !Object.hasOwn(value, "result")) {
		console.log(
			JSON.stringify({
				event: "rpc_rejected",
				method,
				status: response.status,
				code: typeof value.error?.code === "number" ? value.error.code : null,
				accountAbstractionCode:
					typeof value.error?.message === "string"
						? (value.error.message.match(/\bAA\d{2}\b/)?.[0] ?? null)
						: null,
			}),
		);
		throw Error("chain_request_unavailable");
	}
	return value.result;
}
async function derive(owner: Address) {
	const ports = createCetaneChainPorts(config.chainDescriptors, {
		maxRequests: 40,
		maxConcurrency: 2,
		retry: { attempts: 1, delayMs: 0 },
		timeoutMs: 12000,
		fetch: async (request) => {
			await admit("rpc", 3000);
			return fetch(request);
		},
	})[0]!;
	const runtime = createKernelRuntime({
		deployment: kernelDeployment({ chainId: CHAIN_ID }),
		operator: ownerOperator({
			key: kernelKey({
				validator: config.ecdsaValidator,
				account: {
					address: owner,
					sign: async () => {
						throw Error("wallet_signature_required");
					},
				},
			}),
		}),
		reads: ports.reads,
	});
	const bound = await runtime.bindAccount({
		initialPackages: runtime.packages,
		accountIndex: "0",
	});
	return {
		account: bound.account.toLowerCase(),
		factory: bound.factory,
		data: bound.factoryDeployCalldata,
	};
}
const cookie = (token: string, age = 3600) =>
	`__Host-dca=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;
async function session(raw: string) {
	const token = raw.match(/(?:^|;\s*)__Host-dca=([a-f0-9]{64})(?:;|$)/)?.[1];
	if (!token) throw Error("wallet_login_required");
	const r = await pool.query(
		"SELECT * FROM dca_wallet_sessions WHERE digest=$1 AND expires>$2",
		[digest(token), now()],
	);
	if (!r.rows[0]) throw Error("wallet_login_required");
	return r.rows[0];
}
function publicSession(s: any) {
	return {
		token: "cookie",
		owner: s.owner,
		account: s.account,
		expiresAt: Number(s.expires),
		deployment: s.deployment,
		chains: {
			[CHAIN_ID]: {
				publicRpcUrls: [`${ORIGIN}/api/rpc/read`],
				bundlerUrl: `${ORIGIN}/api/rpc/bundler`,
			},
		},
	};
}
const server = createServer(async (req, res) => {
	const json = (value: unknown, status = 200) => {
		res.writeHead(status, {
			"content-type": "application/json",
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
		});
		res.end(JSON.stringify(value));
	};
	try {
		if (req.headers.host !== "127.0.0.1:4320")
			return json({ error: "host_denied" }, 421);
		if (
			(req.headers.origin && req.headers.origin !== ORIGIN) ||
			(req.method === "POST" && req.headers.origin !== ORIGIN)
		)
			return json({ error: "origin_denied" }, 403);
		const url = new URL(req.url!, ORIGIN);
		if (req.method === "GET" && url.pathname === "/api/health")
			return json({ status: "ok", chainId: CHAIN_ID });
		let size = 0;
		const chunks: Buffer[] = [];
		for await (const part of req) {
			size += part.length;
			if (size > 32768) return json({ error: "request_too_large" }, 413);
			chunks.push(part);
		}
		const raw = Buffer.concat(chunks).toString();
		const body = raw ? JSON.parse(raw) : {};
		if (req.method === "POST" && url.pathname === "/api/login/challenge") {
			await admit("login", 200);
			const owner = address(body.owner),
				nonce = randomBytes(24).toString("hex"),
				expires = now() + 300;
			await pool.query("INSERT INTO dca_login_challenges VALUES($1,$2,$3)", [
				nonce,
				owner,
				expires,
			]);
			return json({ nonce, message: loginMessage(owner, nonce, expires) });
		}
		if (req.method === "POST" && url.pathname === "/api/login/complete") {
			await admit("login", 200);
			if (
				!/^[a-f0-9]{48}$/.test(body.nonce) ||
				!/^0x[\da-f]{130}$/i.test(body.signature)
			)
				throw Error("wallet_proof_invalid");
			const r = await pool.query(
				"DELETE FROM dca_login_challenges WHERE nonce=$1 AND expires>$2 RETURNING *",
				[body.nonce, now()],
			);
			const challenge = r.rows[0];
			if (!challenge) throw Error("wallet_proof_expired");
			const signer = await recoverAddress({
				hash: hashMessage(
					loginMessage(
						challenge.owner,
						challenge.nonce,
						Number(challenge.expires),
					),
				),
				signature: body.signature as Hex,
			});
			if (signer.toLowerCase() !== challenge.owner)
				throw Error("wallet_proof_invalid");
			const deployment = await derive(challenge.owner);
			const api = await backend.createSession({
				userId: challenge.owner,
				account: deployment.account as Address,
			});
			const token = randomBytes(32).toString("hex");
			const s = {
				owner: challenge.owner,
				account: deployment.account,
				deployment,
				expires: api.expiresAt,
			};
			await pool.query(
				"INSERT INTO dca_wallet_sessions VALUES($1,$2,$3,$4,$5,$6)",
				[digest(token), s.owner, s.account, deployment, api.token, s.expires],
			);
			res.setHeader("set-cookie", cookie(token));
			return json(publicSession(s));
		}
		const s = await session(req.headers.cookie ?? "");
		if (req.method === "GET" && url.pathname === "/api/session")
			return json(publicSession(s));
		if (req.method === "POST" && url.pathname === "/api/logout") {
			await pool.query("DELETE FROM dca_wallet_sessions WHERE digest=$1", [
				s.digest,
			]);
			res.setHeader("set-cookie", cookie("", 0));
			return json({ signedOut: true });
		}
		if (req.method === "GET" && url.pathname === "/api/account") {
			await admit(`account:${s.owner}`, 60);
			const deployed =
				(await rpc("eth_getCode", [s.account, "latest"])) !== "0x";
			const eth = BigInt(
				await rpc("eth_getBalance", [s.account, "latest"]),
			).toString();
			const usdc = BigInt(
				await rpc("eth_call", [
					{
						to: config.sellToken,
						data: `0x70a08231${s.account.slice(2).padStart(64, "0")}`,
					},
					"latest",
				]),
			).toString();
			return json({ deployed, eth, usdc, sellToken: config.sellToken });
		}
		if (
			req.method === "POST" &&
			["/api/rpc/read", "/api/rpc/bundler"].includes(url.pathname)
		) {
			const bundler = url.pathname.endsWith("bundler");
			if (!rpcAllowed(body, s.account, bundler))
				return json({ error: "rpc_method_denied" }, 403);
			await admit(`rpc:${s.owner}`, 500);
			try {
				return json({
					jsonrpc: "2.0",
					id: body.id,
					result: await rpc(body.method, body.params, bundler),
				});
			} catch {
				return json({
					jsonrpc: "2.0",
					id: body.id,
					error: {
						code: -32000,
						message: "Testnet RPC unavailable or request rejected",
					},
				});
			}
		}
		const path = url.pathname.slice("/api/automation".length);
		if (
			url.pathname.startsWith("/api/automation/") &&
			apiPath(path, req.method!)
		) {
			await admit(`api:${s.owner}`, 1800);
			const response = await fetch(
				`http://127.0.0.1:4317${path}${url.search}`,
				{
					method: req.method,
					headers: {
						authorization: `Bearer ${s.api_token}`,
						"content-type": "application/json",
					},
					body: req.method === "GET" ? undefined : raw,
					signal: AbortSignal.timeout(35000),
					redirect: "error",
				},
			);
			res.writeHead(response.status, {
				"content-type": "application/json",
				"cache-control": "no-store",
			});
			res.end(await response.text());
			return;
		}
		return json({ error: "not_found" }, 404);
	} catch (e) {
		const code =
			e instanceof Error && /^[a-z_]{1,60}$/.test(e.message)
				? e.message
				: "request_unavailable";
		json(
			{ error: code },
			code === "wallet_login_required"
				? 401
				: code === "request_budget_exhausted"
					? 429
					: 409,
		);
	}
});
server.listen(4320, "127.0.0.1");
const cleanup = setInterval(() => {
	void pool
		.query("DELETE FROM dca_login_challenges WHERE expires<$1;", [now()])
		.catch(() => {});
	void pool
		.query("DELETE FROM dca_wallet_sessions WHERE expires<$1", [now()])
		.catch(() => {});
	void pool
		.query("DELETE FROM dca_gateway_budgets WHERE window_id<$1", [
			Math.floor(now() / 600) - 1,
		])
		.catch(() => {});
}, 600000);
process.on("SIGTERM", () => {
	clearInterval(cleanup);
	server.close(() => {
		void pool.end();
	});
});
