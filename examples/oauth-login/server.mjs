/**
 * Serves the example on loopback: the two pages, their esbuild bundles, and the
 * issuer configuration. Shared by `run.mjs` and the portal's end-to-end test.
 *
 * @author taek <leekt216@gmail.com>
 */
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = fileURLToPath(new URL(".", import.meta.url));

export async function startOAuthLoginExample({
  issuer,
  clientId = null,
  // Optional Grant demo: createCetaneChainPorts configuration and a requestPermission input.
  chains = null,
  permission = null,
  port = 0,
  host = "localhost",
}) {
  const bundles = await build({
    entryPoints: [`${HERE}app.js`, `${HERE}callback.js`],
    bundle: true,
    format: "esm",
    platform: "browser",
    // Inside this repository the SDK resolves to its sources; an adopter
    // installs the built package and needs no condition.
    conditions: ["oaath-source"],
    outdir: "/",
    write: false,
    logLevel: "silent",
  });
  const files = new Map([
    ["/", { type: "text/html", body: await readFile(`${HERE}index.html`) }],
    ["/callback", { type: "text/html", body: await readFile(`${HERE}callback.html`) }],
    [
      "/config.json",
      { type: "application/json", body: JSON.stringify({ issuer, clientId, chains, permission }) },
    ],
    ...bundles.outputFiles.map((file) => [
      file.path,
      { type: "text/javascript", body: file.contents },
    ]),
  ]);
  const server = createServer((request, response) => {
    const file = files.get(new URL(request.url ?? "/", "http://localhost").pathname);
    if (!file) return response.writeHead(404).end();
    response.writeHead(200, { "content-type": file.type, "cache-control": "no-store" });
    response.end(file.body);
  });
  await new Promise((resolve) =>
    server.listen(port, host === "localhost" ? "127.0.0.1" : host, resolve),
  );
  const address = server.address();
  return {
    url: `http://${host}:${address.port}`,
    issuer,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
