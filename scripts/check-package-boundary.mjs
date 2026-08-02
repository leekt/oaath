import { readFile } from "node:fs/promises";
import { validatePackageBoundary } from "./package-boundary.mjs";

const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

validatePackageBoundary(manifest);
