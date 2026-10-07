/**
 * A static dapp that signs in with OAAth: a page, its redirect page, and their
 * bundles, served on http://localhost so it can use the live portal.
 *
 *   OAATH_ISSUER     default https://oaath.taek.tech
 *   OAATH_CLIENT_ID  optional; otherwise the page registers a client once
 *   OAATH_PORT       default 5174 (0 picks a free port)
 *   OAATH_SMOKE=1    build, serve once, check both pages, and exit
 *
 * @author taek <leekt216@gmail.com>
 */
import { startOAuthLoginExample } from "./server.mjs";

const example = await startOAuthLoginExample({
  issuer: process.env.OAATH_ISSUER ?? "https://oaath.taek.tech",
  clientId: process.env.OAATH_CLIENT_ID ?? null,
  port: Number(process.env.OAATH_PORT ?? 5174),
});
console.log(`Login with OAAth example: ${example.url} (issuer ${example.issuer})`);
if (process.env.OAATH_SMOKE === "1") {
  for (const path of ["/", "/callback", "/app.js", "/callback.js", "/config.json"]) {
    const response = await fetch(`${example.url}${path}`);
    if (!response.ok) throw new Error(`${path} answered ${response.status}`);
  }
  await example.close();
  console.log("oauth-login: ok");
}
