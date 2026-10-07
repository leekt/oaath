import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dca, env, owner } from "./proof-support.js";

const { id } = JSON.parse(readFileSync(".local/proof-plan.json", "utf8"));
const { url } = JSON.parse(readFileSync(".local/public-url.json", "utf8"));
for (const path of ["/health", "/v1/config"]) {
	const r = await fetch(url + path, {
		headers: { authorization: `Bearer ${env.DCA_API_TOKEN}` },
	});
	assert.equal(r.status, 200);
}
assert.equal((await fetch(`${url}/v1/plans`)).status, 401);
assert.equal(
	(
		await fetch(`${url}/v1/plans`, {
			headers: {
				authorization: `Bearer ${env.DCA_API_TOKEN}`,
				origin: "https://unapproved.example",
			},
		})
	).status,
	403,
);
assert.equal((await fetch(`${url}/.local/environment.json`)).status, 404);
const cors = await fetch(`${url}/v1/plans`, {
	method: "OPTIONS",
	headers: {
		origin: url,
		"access-control-request-method": "POST",
		"access-control-request-headers": "authorization,content-type",
	},
});
assert.equal(cors.status, 204);
assert.equal(cors.headers.get("access-control-allow-origin"), url);
for (let i = 0; i < 20; i++) await dca.get(id);
const before = await owner("stats");
const samples: number[] = [];
let next = 0;
const start = performance.now();
await Promise.all(
	Array.from({ length: 16 }, async () => {
		while (next++ < 1000) {
			const t = performance.now();
			await dca.get(id);
			samples.push(performance.now() - t);
		}
	}),
);
const elapsed = performance.now() - start;
const after = await owner("stats");
samples.sort((a, b) => a - b);
assert.equal(after.rpc, before.rpc);
execFileSync(
	"bun",
	[
		"build",
		"sdk/src/index.ts",
		"--target=browser",
		"--minify",
		"--outfile=.local/sdk-root.js",
	],
	{ stdio: "pipe" },
);
execFileSync(
	"bun",
	[
		"build",
		"sdk/src/approval.ts",
		"--target=browser",
		"--minify",
		"--outfile=.local/sdk-approval.js",
	],
	{ stdio: "pipe" },
);
const source = readFileSync(".local/sdk-root.js");
const result = {
	date: new Date().toISOString(),
	environment:
		"local Apple Silicon; release Rust API; PostgreSQL; loopback HTTP; concurrency 16; 20 warmups",
	requests: 1000,
	elapsedMs: +elapsed.toFixed(2),
	requestsPerSecond: +(1000000 / elapsed).toFixed(1),
	p50Ms: +samples[499]?.toFixed(3),
	p95Ms: +samples[949]?.toFixed(3),
	p99Ms: +samples[989]?.toFixed(3),
	statusRpcMethods: after.rpc - before.rpc,
	sdk: {
		rootMinifiedBytes: source.byteLength,
		rootGzipBytes: gzipSync(source).length,
		approvalGzipBytes: gzipSync(readFileSync(".local/sdk-approval.js")).length,
		rootRuntimeDependencies: 0,
	},
	tailnet: {
		health: true,
		authenticatedApi: true,
		authenticationRequired: true,
		exactOrigin: true,
		privateFilesExcluded: true,
	},
};
mkdirSync("evidence", { recursive: true });
writeFileSync(
	"evidence/local-measurements.json",
	`${JSON.stringify(result, null, 2)}\n`,
);
console.log(JSON.stringify(result, null, 2));
