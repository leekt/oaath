import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";
import test from "node:test";
import QRCode from "qrcode";
import { OneShotPairing, servePairingSecret } from "./demo-routes.mjs";

const start = async (listener) => {
  const server = createServer((incoming, outgoing) => {
    Promise.resolve(listener(incoming, outgoing)).catch(() => {
      outgoing.writeHead(500).end();
    });
  });
  await new Promise((resolve) => server.listen(0, "0.0.0.0", resolve));
  return {
    server,
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
};

test("pairing secret route requires loopback socket and fixed same-origin and closes on consumption or expiry", async () => {
  const pairingCode = randomBytes(24).toString("base64url");
  let consumed = false;
  let expired = false;
  let port = 0;
  const fixture = await start(async (incoming, outgoing) => {
    const pathname = new URL(incoming.url, "http://example.invalid").pathname;
    if (
      await servePairingSecret({
        incoming,
        outgoing,
        pathname,
        allowedOrigins: new Set([`http://127.0.0.1:${port}`]),
        pairingAvailable: () => !consumed && !expired,
        pairingLink: `oaath-demo://pair?relay=http%3A%2F%2F192.0.2.1%3A${port}&code=${pairingCode}`,
        expiresAt: Date.now() + 60_000,
        renderQr: (value) =>
          QRCode.toDataURL(value, { type: "image/png", errorCorrectionLevel: "M", margin: 2 }),
      })
    )
      return;
    outgoing.writeHead(404).end();
  });
  port = fixture.port;
  const loopback = `http://127.0.0.1:${port}/demo/pairing-secret`;
  const post = (url, origin, headers = {}) =>
    fetch(url, { method: "POST", headers: { origin, ...headers }, body: "{}" });
  try {
    const response = await post(loopback, `http://127.0.0.1:${port}`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.deepEqual(Object.keys(body), ["expiresAt", "pairingLink", "qrDataUrl", "version"]);
    assert.equal(body.version, "oaath.demo-pairing-secret/v1");
    assert.match(body.pairingLink, /^oaath-demo:\/\/pair\?/u);
    assert.match(body.qrDataUrl, /^data:image\/png;base64,/u);

    assert.equal((await post(loopback, "http://attacker.invalid")).status, 403);
    // Forwarding and Host-like headers cannot turn a non-same-origin request
    // into an authorized one, even though its real socket is loopback.
    assert.equal(
      (
        await post(loopback, "http://attacker.invalid", {
          "x-forwarded-for": "127.0.0.1",
          "x-forwarded-host": `127.0.0.1:${port}`,
        })
      ).status,
      403,
    );

    const lan = Object.values(networkInterfaces())
      .flatMap((entries) => entries ?? [])
      .find((entry) => entry.family === "IPv4" && !entry.internal)?.address;
    assert.ok(lan, "non-loopback address required for socket-bound route test");
    assert.equal(
      (
        await post(`http://${lan}:${port}/demo/pairing-secret`, `http://127.0.0.1:${port}`, {
          host: `127.0.0.1:${port}`,
          "x-forwarded-for": "127.0.0.1",
        })
      ).status,
      403,
    );

    consumed = true;
    assert.equal((await post(loopback, `http://127.0.0.1:${port}`)).status, 410);
    consumed = false;
    expired = true;
    assert.equal((await post(loopback, `http://127.0.0.1:${port}`)).status, 410);
  } finally {
    await fixture.close();
  }
});

test("pairing reservation is atomic across concurrent handlers", async () => {
  const pairing = new OneShotPairing({ hash: "expected", expiresAt: 100 });
  assert.equal(pairing.available(1), true);
  const credentials = [];
  const devices = new Map();
  const handle = async (index) => {
    pairing.reserve({ hash: "expected", now: 1 });
    await Promise.resolve();
    const credential = `credential-${index}`;
    credentials.push(credential);
    devices.set(credential, { index });
    return credential;
  };
  const settled = await Promise.allSettled([handle(1), handle(2)]);
  assert.equal(settled.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(settled.filter(({ status }) => status === "rejected").length, 1);
  assert.equal(credentials.length, 1);
  assert.equal(devices.size, 1);
  assert.equal(pairing.available(1), false);
  assert.equal(new OneShotPairing({ hash: "expected", expiresAt: 1 }).available(1), false);
});
