import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const mode = process.argv[2];
const settings = JSON.parse(
	readFileSync(new URL("../.local/environment.json", import.meta.url)),
);
const clean = Object.fromEntries(
	Object.entries(process.env).filter(
		([k]) =>
			!/(INFURA|ALCHEMY|PARITY_RPC|ZERODEV|RPC_URL|PRIVATE_KEY|MNEMONIC)/i.test(
				k,
			),
	),
);
const command =
	mode === "api"
		? process.env.AUTOMATION_RELEASE === "1"
			? "./target/release/automation-api"
			: "./target/debug/automation-api"
		: process.execPath;
const args =
	mode === "api"
		? []
		: [mode === "web" ? "examples/dca/server.ts" : "runtime/src/main.ts"];
const child = spawn(command, args, {
	env: { ...clean, ...settings },
	stdio: "inherit",
});
writeFileSync(
	new URL(`../.local/${mode}.pid`, import.meta.url),
	String(child.pid),
);
for (const signal of ["SIGINT", "SIGTERM"])
	process.on(signal, () => child.kill(signal));
child.on("exit", (code) => process.exit(code ?? 1));
