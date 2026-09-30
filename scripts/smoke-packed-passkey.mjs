/** Packed browser-only enrolment and signing through Chromium's virtual authenticator. */
import { createConsumer, run } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "passkey",
  packages: ["@oaath/protocol", "@oaath/sdk"],
  dependencies: {
    esbuild: "0.28.1",
    "puppeteer-core": "25.5.0",
    viem: "2.55.8",
    "@noble/curves": "1.9.1",
  },
  files: {
    "surface.ts": `
import { enrolWebAuthnCredential, type EnrolledWebAuthnCredential } from "@oaath/sdk/kernel";
import type { OperatorCredentialProfile } from "@oaath/protocol";
export async function enrol(signal: AbortSignal): Promise<OperatorCredentialProfile> {
  const value: EnrolledWebAuthnCredential = await enrolWebAuthnCredential({ rpId: "example.test", userName: "operator", signal });
  return value.profile;
}
`,
    "browser.mjs": String.raw`
import { enrolWebAuthnCredential, kernelKey } from "@oaath/sdk/kernel";
import { p256 } from "@noble/curves/nist.js";
import { hexToBytes, keccak256, toHex } from "viem";
const assert = (value, code) => { if (!value) throw new Error(code); };
const bytes = id => Uint8Array.from(atob(id.replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0));
globalThis.passkeySmoke = async () => {
  assert(typeof Buffer === "undefined" && typeof process === "undefined", "Node global leaked");
  const enrolment = await enrolWebAuthnCredential({ rpId: "example.test", userName: "operator" });
  assert(enrolment.profile.authenticatorIdHash === keccak256(bytes(enrolment.credentialId)), "credential hash mismatch");
  const key = kernelKey({ kind: "webauthn", credential: enrolment.profile, credentialId: enrolment.credentialId,
    rpId: "example.test", origin: location.origin,
    authenticate: async request => {
      const credential = await navigator.credentials.get({ publicKey: {
        rpId: request.rpId, challenge: hexToBytes(request.hash), userVerification: "required",
        allowCredentials: [{ type: "public-key", id: bytes(request.credentialId) }], timeout: 10000,
      } });
      const response = credential.response;
      const signature = p256.Signature.fromDER(new Uint8Array(response.signature));
      const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
      return { authenticatorData: toHex(new Uint8Array(response.authenticatorData)), clientDataJSON,
        responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
        r: toHex(signature.r, { size: 32 }), s: toHex(signature.s, { size: 32 }) };
    },
  });
  const hash = "0x" + "42".repeat(32);
  const signature = await key.sign(hash);
  assert(await key.verify(hash, signature), "enrolled key could not sign");
  try { await enrolWebAuthnCredential({ rpId: "example.test", userName: "operator", excludeCredentialIds: [enrolment.credentialId] }); throw new Error("duplicate accepted"); }
  catch (error) { assert(error.code === "already-registered", "duplicate code lost"); assert(error.cause instanceof DOMException && error.cause.name === "InvalidStateError", "browser cause lost"); assert(!Object.keys(error).includes("cause"), "cause became enumerable"); }
  try { await enrolWebAuthnCredential({ rpId: "other.example.test", userName: "operator" }); throw new Error("wrong RP accepted"); }
  catch (error) { assert(error.code === "rp-mismatch", "RP code lost"); }
  return { enrolled: true, signed: true, excluded: true, parentRp: true };
};
`,
    "run.mjs": String.raw`
import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { build } from "esbuild";
import puppeteer from "puppeteer-core";
const bundle = await build({ entryPoints: ["browser.mjs"], bundle: true, write: false, platform: "browser", format: "esm" });
let browser;
try {
  const origin = "https://wallet.example.test";
  const candidates = [process.env.PUPPETEER_EXECUTABLE_PATH, process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"].filter(Boolean);
  let executablePath;
  for (const path of candidates) { try { await access(path); executablePath = path; break; } catch {} }
  assert.ok(executablePath, "Chrome unavailable");
  browser = await puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox", "--disable-background-networking"] });
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on("request", request => {
    if (request.url() === origin + "/browser.js") return request.respond({ status: 200, contentType: "text/javascript", body: bundle.outputFiles[0].text });
    if (request.url() === origin + "/") return request.respond({ status: 200, contentType: "text/html", body: '<!doctype html><script type="module" src="/browser.js"></script>' });
    return request.abort();
  });
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(origin, { timeout: 10000 });
  await page.waitForFunction(() => typeof globalThis.passkeySmoke === "function", { timeout: 10000 });
  assert.deepEqual(await page.evaluate(() => globalThis.passkeySmoke()), { enrolled: true, signed: true, excluded: true, parentRp: true });
  console.log("packed Chromium passkey: parent RP enrolment, raw-ID hash parity, signing, duplicate/RP rejection; no Node globals");
} finally {
  await browser?.close();
}
`,
  },
});
try {
  consumer.typecheck();
  process.stdout.write(
    run(process.execPath, ["run.mjs"], { cwd: consumer.directory, timeout: 90_000 }),
  );
} finally {
  await consumer.cleanup();
}
