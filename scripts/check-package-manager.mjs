import { readFileSync } from "node:fs";

const { packageManager } = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
const userAgent = process.env.npm_config_user_agent ?? "";
const expectedAgent = packageManager.replace("@", "/");

if (userAgent.split(" ")[0] !== expectedAgent) {
  console.error(`This repository requires ${packageManager}. Run bun install with that version.`);
  process.exit(1);
}
