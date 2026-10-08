/** Start only owned local fixtures and the two-part product. No live RPC settings are inherited. */
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";

const root = new URL("../", import.meta.url).pathname;
process.chdir(root);
mkdirSync(".local", { recursive: true });
const run = (command: string, args: string[], env = process.env) =>
	execFileSync(command, args, { cwd: root, env, stdio: "pipe" }).toString();
const children: ChildProcess[] = [];
const clean = Object.fromEntries(
	Object.entries(process.env).filter(
		([k]) =>
			!/(INFURA|ALCHEMY|PARITY_RPC|ZERODEV|RPC_URL|PRIVATE_KEY|MNEMONIC)/i.test(
				k,
			),
	),
);
function start(args: string[], extra: Record<string, string> = {}) {
	const c = spawn(process.execPath, args, {
		cwd: root,
		env: { ...clean, ...extra },
		stdio: "inherit",
	});
	children.push(c);
	return c;
}
async function ready(url: string, token?: string) {
	for (let n = 0; n < 120; n++) {
		try {
			const r = await fetch(url, {
				method: token ? "POST" : "GET",
				headers: token ? { authorization: `Bearer ${token}` } : undefined,
				signal: AbortSignal.timeout(1000),
			});
			if (r.ok) return;
		} catch {}
		await new Promise((r) => setTimeout(r, 500));
	}
	throw Error("service_start_timeout");
}
try {
	run("bun", ["install", "--frozen-lockfile"]);
	run("bun", ["run", "build"]);
	const cargo = run("rustup", ["which", "cargo"]).trim();
	const rustPath = cargo.slice(0, cargo.lastIndexOf("/"));
	run(cargo, ["build", "--release"], {
		...process.env,
		PATH: `${rustPath}:${process.env.PATH}`,
	});
	let reuse = false;
	if (existsSync(".local/environment.json")) {
		const e = JSON.parse(readFileSync(".local/environment.json", "utf8"));
		try {
			reuse = (
				await fetch("http://127.0.0.1:4319/stats", {
					method: "POST",
					headers: { authorization: `Bearer ${e.DCA_OWNER_TOKEN}` },
					signal: AbortSignal.timeout(1000),
				})
			).ok;
		} catch {}
	}
	if (!reuse) {
		if (!existsSync(".local/pg/PG_VERSION"))
			run("initdb", ["-D", ".local/pg", "-A", "trust", "--no-locale"]);
		try {
			run("pg_ctl", ["-D", ".local/pg", "status"]);
		} catch {
			run("pg_ctl", [
				"-D",
				".local/pg",
				"-l",
				".local/postgres.log",
				"-o",
				"-h 127.0.0.1 -p 55437",
				"start",
			]);
		}
		const database = `automation_${Date.now()}`;
		run("createdb", ["-h", "127.0.0.1", "-p", "55437", database]);
		start(["scripts/local-chain.ts"], {
			AUTOMATION_DATABASE_URL: `postgres://${encodeURIComponent(userInfo().username)}@127.0.0.1:55437/${database}`,
		});
		for (let n = 0; n < 120; n++) {
			await new Promise((r) => setTimeout(r, 500));
			if (existsSync(".local/environment.json")) {
				const e = JSON.parse(readFileSync(".local/environment.json", "utf8"));
				if (e.AUTOMATION_DATABASE_URL.endsWith(`/${database}`)) break;
			}
		}
	}
	const e = JSON.parse(readFileSync(".local/environment.json", "utf8"));
	await ready("http://127.0.0.1:4319/stats", e.DCA_OWNER_TOKEN);
	run("bun", ["scripts/tailnet.mjs"]);
	for (const mode of ["api", "runtime"]) {
		try {
			run("bun", ["scripts/stop.mjs", mode]);
		} catch {}
		start(["scripts/run.mjs", mode], { AUTOMATION_RELEASE: "1" });
	}
	await ready("http://127.0.0.1:4317/health");
	const { url, webUrl } = JSON.parse(
		readFileSync(".local/public-url.json", "utf8"),
	);
	await ready(`${url}/health`);
	const r = await fetch(`${url}/v1/config`, {
		headers: { authorization: `Bearer ${e.AUTOMATION_API_TOKEN}` },
	});
	if (!r.ok) throw Error("tailnet_api_verification_failed");
	try {
		run("bun", ["scripts/stop.mjs", "web"]);
	} catch {}
	start(["scripts/run.mjs", "web"]);
	await ready(webUrl);
	console.log(`Automation ready: ${webUrl}`);
	await new Promise<void>((resolve) => {
		process.once("SIGINT", resolve);
		process.once("SIGTERM", resolve);
	});
} catch {
	console.error(
		"Local startup failed; check local tool availability and owned fixture logs.",
	);
	process.exitCode = 1;
} finally {
	for (const c of children) c.kill("SIGTERM");
}
