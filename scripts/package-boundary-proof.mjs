import assert from "node:assert/strict";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const visited = new Set(),
	names = new Set();
const cetaneVersion = JSON.parse(readFileSync("vendor/provenance.json")).find(
	(p) => p.name === "cetane",
).version;
function visit(name, from) {
	let parent = dirname(from instanceof URL ? fileURLToPath(from) : from);
	let dir;
	for (;;) {
		const candidate = join(parent, "node_modules", name);
		if (existsSync(join(candidate, "package.json"))) {
			dir = candidate;
			break;
		}
		const next = dirname(parent);
		if (next === parent) throw Error(`package_missing:${name}`);
		parent = next;
	}
	dir = realpathSync(dir);
	if (visited.has(dir)) return;
	visited.add(dir);
	const p = JSON.parse(readFileSync(join(dir, "package.json")));
	if (p.name === "cetane") assert.equal(p.version, cetaneVersion);
	names.add(p.name);
	for (const dependency of Object.keys(p.dependencies ?? {}))
		visit(dependency, join(dir, "package.json"));
}
for (const name of ["@oaath/sdk", "@oaath/protocol"]) {
	visit(name, new URL("../package.json", import.meta.url));
	visit(name, new URL("../.local/consumer/package.json", import.meta.url));
}
for (const name of ["@oaath/server", "moesi"])
	visit(name, new URL("../runtime/package.json", import.meta.url));
assert.ok(!names.has("viem"));
const r = await import(
	"../.local/consumer/node_modules/@oaath/automation/dist/index.js"
);
const w = await import(
	"../.local/consumer/node_modules/@oaath/automation/dist/wallet.js"
);
assert.equal(typeof w.createWalletOwner, "function");
const browser = await import(
	"../.local/consumer/node_modules/@oaath/automation/dist/react.js"
);
assert.equal(typeof browser.AutomationCreator, "function");
assert.deepEqual(Object.keys(r).sort(), [
	"AutomationError",
	"createAutomation",
]);
console.log(
	`Packed root, React and wallet exports load; ${names.size} production dependency names contain no viem.`,
);
writeFileSync(
	".local/package-evidence.json",
	JSON.stringify(
		{
			publicExports: Object.keys(r),
			cetaneVersion,
			productionViemDependencies: 0,
			productionDependencyNames: [...names].sort(),
		},
		null,
		2,
	),
);
