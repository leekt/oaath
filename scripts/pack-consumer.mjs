import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

execFileSync("bun", ["run", "--cwd", "sdk", "build"], { stdio: "inherit" });
execFileSync(
	"bun",
	["pm", "pack", "--destination", "../vendor", "--ignore-scripts"],
	{ cwd: "sdk", stdio: "pipe" },
);
const provenance = JSON.parse(readFileSync("vendor/provenance.json"));
const peerPins = Object.fromEntries(
	provenance
		.filter((p) => ["@oaath/sdk", "@oaath/protocol", "cetane"].includes(p.name))
		.map((p) => [p.name, `file:../../vendor/${p.file}`]),
);
const file = "vendor/oaath-automation-0.1.0.tgz",
	data = readFileSync(file),
	digest = createHash("sha256").update(data).digest("hex");
const pinned = `oaath-automation-0.1.0-${digest.slice(0, 12)}.tgz`;
copyFileSync(file, `vendor/${pinned}`);
mkdirSync(".local/consumer", { recursive: true });
writeFileSync(
	".local/consumer/package.json",
	JSON.stringify({
		name: "automation-consumer",
		private: true,
		type: "module",
		dependencies: {
			"@oaath/automation": `file:../../vendor/${pinned}`,
			...peerPins,
		},
		overrides: peerPins,
	}),
);
execFileSync("bun", ["install"], { cwd: ".local/consumer", stdio: "inherit" });
writeFileSync(
	".local/consumer/artifact.json",
	JSON.stringify({ file: pinned, sha256: digest }),
);
