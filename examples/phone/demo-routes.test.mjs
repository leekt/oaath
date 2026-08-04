import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";
import test from "node:test";
import QRCode from "qrcode";
import {
  compareOperationIds,
  markInboxTerminal,
  pendingInbox,
  serveDemoInbox,
  servePairingSecret,
} from "./demo-routes.mjs";

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

const request = (url, token) =>
  fetch(url, {
    headers: token === null ? {} : { authorization: `Bearer ${token}` },
  });

const summary = (operationId, displayPayload, expiresAt) => ({
  inboxState: "pending",
  inboxSummary: Object.freeze({ operationId, displayPayload, expiresAt }),
});

test("actual inbox HTTP route is exact, device-bound, read-only, filtered, sorted, and capped", async () => {
  const credential = randomBytes(32).toString("base64url");
  const now = 1_900_000_000_000;
  const records = new Map();
  for (let index = 0; index < 25; index += 1) {
    const operationId = `request-${String(24 - index).padStart(2, "0")}`;
    records.set(
      operationId,
      summary(operationId, `CODE${String(index).padStart(4, "0")}`, now + 1_000 + (index % 3)),
    );
  }
  records.set("expired", summary("expired", "EXPR0000", now));
  records.set("approved", {
    ...summary("approved", "APPR0000", now + 5_000),
    inboxState: "terminal",
  });
  records.set("rejected", {
    ...summary("rejected", "REJT0000", now + 5_000),
    inboxState: "terminal",
  });
  const effects = { creates: 0, decisions: 0, submissions: 0 };
  const activeDevice = { credential };
  const fixture = await start((incoming, outgoing) => {
    const pathname = new URL(incoming.url, "http://example.invalid").pathname;
    if (
      serveDemoInbox({
        incoming,
        outgoing,
        pathname,
        activeDevice,
        records,
        now: () => now,
      })
    )
      return;
    outgoing.writeHead(404).end();
  });
  try {
    const url = `http://127.0.0.1:${fixture.port}/demo/inbox`;
    for (const token of [
      null,
      randomBytes(32).toString("base64url"),
      "demo-client-token",
      "demo-owner-token",
    ])
      assert.equal((await request(url, token)).status, 401);

    const response = await request(url, credential);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const text = await response.text();
    const body = JSON.parse(text);
    assert.deepEqual(Object.keys(body), ["requests", "version"]);
    assert.equal(body.version, "oaath.demo-inbox/v1");
    assert.equal(body.requests.length, 20);
    assert.ok(
      body.requests.every(
        (item) =>
          JSON.stringify(Object.keys(item)) ===
          JSON.stringify(["displayPayload", "expiresAt", "operationId"]),
      ),
    );
    const sorted = [...body.requests].sort(
      (left, right) =>
        left.expiresAt - right.expiresAt ||
        compareOperationIds(left.operationId, right.operationId),
    );
    assert.deepEqual(body.requests, sorted);
    assert.equal(
      body.requests.some((item) => item.operationId === "expired"),
      false,
    );
    assert.equal(
      body.requests.some((item) => item.operationId === "approved"),
      false,
    );
    assert.equal(
      body.requests.some((item) => item.operationId === "rejected"),
      false,
    );
    for (const forbidden of [
      "digest",
      "consent",
      "signature",
      "credential",
      "pairingCode",
      "redirectUri",
      "provider",
    ])
      assert.equal(text.includes(forbidden), false);
    assert.deepEqual(effects, { creates: 0, decisions: 0, submissions: 0 });

    const pending = body.requests[0].operationId;
    markInboxTerminal(records, pending);
    const afterDecision = await (await request(url, credential)).json();
    assert.equal(
      afterDecision.requests.some((item) => item.operationId === pending),
      false,
    );
    assert.equal(records.get(pending).inboxSummary.operationId, pending);
  } finally {
    await fixture.close();
  }
});

test("equal-expiry inbox ids use locale-independent ASCII order", () => {
  const expiresAt = 1_900_000_000_000;
  const records = new Map(
    ["a", "_", "A", "0"].map((operationId, index) => [
      operationId,
      summary(operationId, `CODE000${index}`, expiresAt),
    ]),
  );
  assert.deepEqual(
    pendingInbox(records, expiresAt - 1).map(({ operationId }) => operationId),
    ["0", "A", "_", "a"],
  );
});

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
