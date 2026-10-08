import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

for (const dir of [
	"dist/hosted",
	"dist/server/runtime/src",
	"dist/server/vendor",
])
	mkdirSync(dir, { recursive: true });
const build = (input, output, target) =>
	execFileSync(
		"bun",
		[
			"build",
			input,
			"--outfile",
			output,
			"--target",
			target,
			"--minify",
			"--external",
			"pg-native",
		],
		{ stdio: "inherit" },
	);
build("examples/dca/hosted/app.tsx", "dist/hosted/app.js", "browser");
build("examples/dca/hosted/server.ts", "dist/server/gateway.mjs", "node");
build("runtime/src/main.ts", "dist/server/runtime/src/main.mjs", "node");
for (const name of ["DcaFactory", "DcaExecutor"])
	copyFileSync(`vendor/${name}.json`, `dist/server/vendor/${name}.json`);
copyFileSync("sdk/dist/styles.css", "dist/hosted/automation.css");
const html = readFileSync("examples/dca/src/index.html", "utf8").replace(
	"</style>",
	".wallet-workspace{padding-block:12px 48px;margin-bottom:48px;border-bottom:1px solid #d6e0e8}.wallet-workspace .wallet-title{font-size:21px;margin:0 0 16px;letter-spacing:-.015em}.wallet-workspace a{text-decoration:underline;text-underline-offset:3px}.wallet-workspace details{margin:16px 0 24px}.wallet-workspace summary{cursor:pointer;margin-bottom:16px}.wallet-hint{font-size:14px;margin-top:18px!important}.wallet-address{display:block;overflow-wrap:anywhere;margin:16px 0}.wallet-setup{margin-bottom:24px}.wallet-workspace dl{margin:0}.wallet-workspace dl div{padding:14px 0;border-top:1px solid #d6e0e8}.wallet-workspace dt{font-size:13px;color:#526578}.wallet-workspace dd{margin:4px 0 0}.wallet-workspace aside{padding:28px;background:#edf3fa}@media(max-width:720px){.wallet-workspace .automation-columns{gap:32px}.wallet-workspace .automation-heading{flex-wrap:wrap}}</style>",
);
writeFileSync("dist/hosted/index.html", html);
