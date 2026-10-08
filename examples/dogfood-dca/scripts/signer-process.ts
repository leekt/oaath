import { readFileSync } from "node:fs";

Object.assign(
	process.env,
	JSON.parse(readFileSync(".local/environment.json", "utf8")),
);
const { registry } = await import("../runtime/src/signer.js");
const { pool } = await import("../runtime/src/store.js");
try {
	const input = JSON.parse(readFileSync(0, "utf8"));
	const result =
		input.action === "create"
			? await registry.create(input.identity)
			: input.action === "sign"
				? await registry.sign(input.identity, input.address, input.hash)
				: await registry.recover(input.identity, input.address);
	console.log(JSON.stringify({ ok: true, result }));
} catch (e) {
	console.log(
		JSON.stringify({
			ok: false,
			code: (e as { code?: string }).code ?? "failed",
		}),
	);
} finally {
	await pool.end();
}
