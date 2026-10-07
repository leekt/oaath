import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = join(root, "vendor");
const pkg = JSON.parse(readFileSync(join(root, "package.json")));
mkdirSync(output, { recursive: true });
const run = (cmd, args, cwd) =>
	execFileSync(cmd, args, { cwd, stdio: "pipe", env: process.env }).toString();
const paths = [
	["@oaath/protocol", ".local/oaath-automation/packages/protocol"],
	["@oaath/sdk", ".local/oaath-automation/packages/sdk"],
	["@oaath/server", ".local/oaath-automation/packages/server"],
	["@oaath/testing", ".local/oaath-automation/packages/testing"],
	["moesi", ".local/moesi-automation/packages/moesi"],
];
const provenance = [];
for (const [name, path] of paths) {
	const cwd = resolve(root, path);
	run("bun", ["run", "build"], cwd);
	run("bun", ["pm", "pack", "--destination", output, "--ignore-scripts"], cwd);
	const pkg = JSON.parse(readFileSync(join(cwd, "package.json")));
	const original = `${name.replace("@", "").replace("/", "-")}-${pkg.version}.tgz`;
	const data = readFileSync(join(output, original));
	const digest = createHash("sha256").update(data).digest("hex");
	const filename = original.replace(".tgz", `-${digest.slice(0, 12)}.tgz`);
	copyFileSync(join(output, original), join(output, filename));
	provenance.push({
		name,
		version: pkg.version,
		file: filename,
		commit: run("git", ["rev-parse", "HEAD"], cwd).trim(),
		sourceDiffSha256: createHash("sha256")
			.update(run("git", ["diff", "HEAD"], cwd))
			.digest("hex"),
		sourceState: run("git", ["status", "--porcelain"], cwd).trim()
			? "working-tree snapshot; packed artifact is authoritative"
			: "clean commit",
		sha256: digest,
	});
}
const release = JSON.parse(
	run(
		"npm",
		[
			"view",
			`cetane@${pkg.devDependencies.cetane}`,
			"version",
			"dist",
			"--json",
			"--registry=https://registry.npmjs.org",
		],
		root,
	),
);
if (release.version !== pkg.devDependencies.cetane)
	throw Error("cetane_release_version_mismatch");
const response = await fetch(release.dist.tarball, {
	signal: AbortSignal.timeout(30000),
	redirect: "error",
});
if (!response.ok) throw Error("cetane_release_download_failed");
const data = Buffer.from(await response.arrayBuffer());
const integrity = `sha512-${createHash("sha512").update(data).digest("base64")}`;
if (integrity !== release.dist.integrity)
	throw Error("cetane_release_integrity_mismatch");
const digest = createHash("sha256").update(data).digest("hex");
const filename = `cetane-${release.version}-${digest.slice(0, 12)}.tgz`;
writeFileSync(join(output, filename), data);
provenance.push({
	name: "cetane",
	version: release.version,
	file: filename,
	sourceState: "npm registry release",
	tarball: release.dist.tarball,
	integrity,
	sha256: digest,
});
for (const name of ["DcaExecutor", "DcaFactory"]) {
	copyFileSync(
		join(root, "recipes/dca/contracts/out/DcaExecutor.sol", `${name}.json`),
		join(output, `${name}.json`),
	);
}
for (const [from, to] of [
	["Token", "FixtureToken"],
	["Feed", "FixtureFeed"],
])
	copyFileSync(
		join(root, "recipes/dca/contracts/out/DcaExecutor.t.sol", `${from}.json`),
		join(output, `${to}.json`),
	);
writeFileSync(
	join(output, "provenance.json"),
	`${JSON.stringify(provenance, null, 2)}\n`,
);
pkg.overrides = Object.fromEntries(
	provenance
		.filter((p) => p.name !== "moesi")
		.map((p) => [
			p.name,
			p.name === "cetane" ? p.version : `file:vendor/${p.file}`,
		]),
);
for (const p of provenance) {
	if (pkg.devDependencies?.[p.name])
		pkg.devDependencies[p.name] =
			p.name === "cetane" ? p.version : `file:vendor/${p.file}`;
}
writeFileSync(join(root, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
const runtime = JSON.parse(readFileSync(join(root, "runtime/package.json")));
for (const p of provenance) {
	if (p.name === "@oaath/testing") continue;
	runtime.dependencies[p.name] =
		p.name === "cetane" ? p.version : `file:../vendor/${p.file}`;
}
writeFileSync(
	join(root, "runtime/package.json"),
	`${JSON.stringify(runtime, null, 2)}\n`,
);
console.log(`Retained ${provenance.length} exact local and registry artifacts`);
