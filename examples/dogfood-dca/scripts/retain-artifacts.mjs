import { createHash } from "node:crypto";
import {
	mkdirSync,
	readdirSync,
	readFileSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";

const dependencies = JSON.parse(readFileSync("vendor/provenance.json"));
const sdk = JSON.parse(readFileSync(".local/consumer/artifact.json"));
const keep = new Set([...dependencies.map((d) => d.file), sdk.file]);
for (const name of readdirSync("vendor"))
	if (name.endsWith(".tgz") && !keep.has(name)) unlinkSync("vendor/" + name);
const checksums = Object.fromEntries(
	readdirSync("vendor")
		.filter((n) => n !== "checksums.json")
		.sort()
		.map((n) => [
			n,
			createHash("sha256")
				.update(readFileSync("vendor/" + n))
				.digest("hex"),
		]),
);
writeFileSync(
	"vendor/checksums.json",
	JSON.stringify(checksums, null, 2) + "\n",
);
mkdirSync("evidence", { recursive: true });
for (const name of ["recovery", "boundary", "setup-recovery"]) {
	const value = JSON.parse(readFileSync(`.local/${name}-evidence.json`));
	writeFileSync(`evidence/${name}.json`, JSON.stringify(value, null, 2) + "\n");
}
writeFileSync(
	"evidence/sdk-artifact.json",
	JSON.stringify(sdk, null, 2) + "\n",
);
console.log("Retained only exact tested dependency and SDK archives");
