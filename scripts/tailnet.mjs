import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const cli = existsSync("/Applications/Tailscale.app/Contents/MacOS/Tailscale")
	? "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	: "tailscale";
const run = (...args) => execFileSync(cli, args, { encoding: "utf8" });
const status = JSON.parse(run("status", "--json"));
const ip = status.Self.TailscaleIPs.find((ip) => !ip.includes(":")),
	name = status.Self.DNSName.replace(/\.$/, "");
if (!ip || !name) throw Error("tailscale_identity_unavailable");
const current = JSON.parse(run("serve", "status", "--json"));
if (
	current.TCP?.["4317"] &&
	current.TCP["4317"].TCPForward !== "127.0.0.1:4317"
)
	throw Error("tailscale_port_already_owned");
const url = `http://${name}:4317`;
const path = new URL("../.local/environment.json", import.meta.url);
const env = JSON.parse(readFileSync(path, "utf8"));
const config = JSON.parse(readFileSync(env.DCA_CONFIG, "utf8"));
config.origin = url;
env.DCA_ALLOWED_HOSTS = `127.0.0.1:4317,localhost:4317,${ip}:4317,${name}:4317`;
writeFileSync(env.DCA_CONFIG, JSON.stringify(config, null, 2), { mode: 0o600 });
writeFileSync(path, JSON.stringify(env), { mode: 0o600 });
run("serve", "--bg", "--tcp=4317", "tcp://127.0.0.1:4317");
writeFileSync(
	new URL("../.local/public-url.json", import.meta.url),
	JSON.stringify({ url, ip, name }),
);
console.log(url);
