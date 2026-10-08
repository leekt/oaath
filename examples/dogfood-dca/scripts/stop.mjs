import { readFileSync } from "node:fs";

const pid = Number(
	readFileSync(
		new URL(`../.local/${process.argv[2]}.pid`, import.meta.url),
		"utf8",
	),
);
try {
	process.kill(pid, "SIGTERM");
} catch {
	process.exit();
}
for (let n = 0; n < 50; n++) {
	await new Promise((r) => setTimeout(r, 100));
	try {
		process.kill(pid, 0);
	} catch {
		process.exit();
	}
}
try {
	process.kill(pid, "SIGKILL");
} catch {}
