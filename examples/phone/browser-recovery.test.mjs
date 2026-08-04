import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

class MemoryStorage {
  #values = new Map();
  getItem(key) {
    return this.#values.get(key) ?? null;
  }
  setItem(key, value) {
    this.#values.set(key, String(value));
  }
  removeItem(key) {
    this.#values.delete(key);
  }
  snapshot() {
    return [...this.#values.values()];
  }
}

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

function installDocument() {
  const nodes = new Map(
    [
      "status",
      "account",
      "pair",
      "pairing",
      "pairing-qr",
      "pairing-link",
      "unlock",
      "permission",
      "session",
      "owner",
    ].map((id) => [
      id,
      {
        id,
        textContent: "",
        onclick: null,
        hidden: id === "pairing",
        value: "",
        src: "",
        removeAttribute(name) {
          if (name === "src") this.src = "";
        },
      },
    ]),
  );
  globalThis.document = { getElementById: (id) => nodes.get(id) };
  return nodes;
}

test("page has one Pair action plus the four account actions", () => {
  const page = readFileSync(new URL("./page.html", import.meta.url), "utf8");
  const buttonIds = [...page.matchAll(/<button[^>]+id="([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(buttonIds, ["pair", "unlock", "permission", "session", "owner"]);
});

test("Pair click renders the transient QR/link without storing the secret", async () => {
  const storage = new MemoryStorage();
  globalThis.localStorage = storage;
  globalThis.location = { port: "8787" };
  const nodes = installDocument();
  const transient = randomBytes(24).toString("base64url");
  globalThis.fetch = async (path) => {
    if (path === "/demo/pairing-secret")
      return jsonResponse({
        expiresAt: Date.now() + 5_000,
        pairingLink: `oaath-demo://pair?relay=http%3A%2F%2F192.0.2.1%3A8787&code=${transient}`,
        qrDataUrl: `data:image/png;base64,${randomBytes(24).toString("base64")}`,
        version: "oaath.demo-pairing-secret/v1",
      });
    if (path === "/demo/account") return jsonResponse({ error: { code: "phone_not_paired" } }, 409);
    throw new Error(`unexpected API call ${path}`);
  };

  await import(`./browser.js?pair=${Date.now()}`);
  await nodes.get("pair").onclick();
  assert.equal(nodes.get("pairing").hidden, false);
  assert.match(nodes.get("pairing-link").value, /^oaath-demo:\/\/pair\?/u);
  assert.match(nodes.get("pairing-qr").src, /^data:image\/png;base64,/u);
  assert.equal(
    storage.snapshot().some((value) => value.includes("oaath-demo://pair?")),
    false,
  );

  // A later successful pairing status hides and drops both transient values.
  globalThis.fetch = async (path) => {
    if (path === "/demo/account") return jsonResponse({ account: "paired" });
    throw new Error(`unexpected API call ${path}`);
  };
  await new Promise((resolve) => setTimeout(resolve, 1_100));
  assert.equal(nodes.get("pairing").hidden, true);
  assert.equal(nodes.get("pairing-link").value, "");
  assert.equal(nodes.get("pairing-qr").src, "");
});

test("overlapping Pair clicks are latest-wins and leave no stale timers or secrets", async () => {
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  const originalSetInterval = globalThis.setInterval;
  const originalClearInterval = globalThis.clearInterval;
  const timeouts = new Map();
  const intervals = new Map();
  let timerId = 0;
  globalThis.setTimeout = (callback) => {
    const id = ++timerId;
    timeouts.set(id, callback);
    return id;
  };
  globalThis.clearTimeout = (id) => timeouts.delete(id);
  globalThis.setInterval = (callback) => {
    const id = ++timerId;
    intervals.set(id, callback);
    return id;
  };
  globalThis.clearInterval = (id) => intervals.delete(id);

  try {
    globalThis.localStorage = new MemoryStorage();
    globalThis.location = { port: "8787" };
    const nodes = installDocument();
    const requests = [];
    let paired = false;
    globalThis.fetch = async (path) => {
      if (path === "/demo/pairing-secret") {
        const request = deferred();
        requests.push(request);
        return request.promise;
      }
      if (path === "/demo/account")
        return paired
          ? jsonResponse({ account: "paired" })
          : jsonResponse({ error: { code: "phone_not_paired" } }, 409);
      throw new Error(`unexpected API call ${path}`);
    };
    const secret = (code) =>
      jsonResponse({
        expiresAt: Date.now() + 5_000,
        pairingLink: `oaath-demo://pair?relay=http%3A%2F%2F192.0.2.1%3A8787&code=${code}`,
        qrDataUrl: `data:image/png;base64,${Buffer.from(code).toString("base64")}`,
        version: "oaath.demo-pairing-secret/v1",
      });

    await import(`./browser.js?pair-race=${Date.now()}`);
    const first = nodes.get("pair").onclick();
    const second = nodes.get("pair").onclick();
    requests[1].resolve(secret("B"));
    await second;
    requests[0].resolve(secret("A"));
    await first;
    assert.match(nodes.get("pairing-link").value, /code=B$/u);
    assert.equal(timeouts.size, 1);
    assert.equal(intervals.size, 1);

    paired = true;
    await [...intervals.values()][0]();
    assert.equal(nodes.get("pairing").hidden, true);
    assert.equal(nodes.get("pairing-link").value, "");
    assert.equal(timeouts.size, 0);
    assert.equal(intervals.size, 0);

    paired = false;
    const third = nodes.get("pair").onclick();
    const fourth = nodes.get("pair").onclick();
    requests[2].resolve(secret("C"));
    await third;
    assert.equal(nodes.get("pairing-link").value, "");
    assert.equal(timeouts.size, 0);
    assert.equal(intervals.size, 0);
    requests[3].resolve(secret("D"));
    await fourth;
    assert.match(nodes.get("pairing-link").value, /code=D$/u);
    assert.equal(timeouts.size, 1);
    assert.equal(intervals.size, 1);

    [...timeouts.values()][0]();
    assert.equal(nodes.get("pairing").hidden, true);
    assert.equal(nodes.get("pairing-link").value, "");
    assert.equal(timeouts.size, 0);
    assert.equal(intervals.size, 0);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
    globalThis.setInterval = originalSetInterval;
    globalThis.clearInterval = originalClearInterval;
  }
});

test("lost submit response plus browser reload resumes the exact API operation with zero resubmits", async () => {
  const storage = new MemoryStorage();
  globalThis.localStorage = storage;
  const operationId = "prepared-operation-id";
  const userOperationHash = `0x${"31".repeat(32)}`;
  const transactionHash = `0x${"32".repeat(32)}`;
  let operation = null;
  let prepares = 0;
  let submissions = 0;
  let observations = 0;
  globalThis.fetch = async (path, options = {}) => {
    if (path === "/demo/state")
      return jsonResponse({ operation, permission: null, signatureRequest: null });
    if (path === "/demo/session/prepare") {
      prepares += 1;
      operation = { operationId, kind: "session", status: "prepared", userOperationHash };
      return jsonResponse({ operationId, userOperationHash }, 201);
    }
    if (path === "/demo/session/submit") {
      submissions += 1;
      assert.equal(JSON.parse(options.body).operationId, operationId);
      operation = { operationId, kind: "session", status: "unresolved", userOperationHash };
      throw new TypeError("response lost after server-side submission");
    }
    if (path === `/demo/operations/${operationId}`) {
      observations += 1;
      operation = null;
      return jsonResponse({
        status: "included",
        operationId,
        userOperationHash,
        transactionHash,
      });
    }
    throw new Error(`unexpected API call ${path}`);
  };

  let nodes = installDocument();
  await import(`./browser.js?first=${Date.now()}`);
  await nodes.get("session").onclick();
  assert.equal(prepares, 1, nodes.get("status").textContent);
  assert.equal(submissions, 1, nodes.get("status").textContent);
  assert.equal(storage.getItem("oaath-demo-session-operation-v1"), operationId);

  // A reload recreates all page state but preserves browser storage. The next
  // button action asks the read-only state projection and observes the exact id.
  nodes = installDocument();
  await import(`./browser.js?reload=${Date.now()}`);
  await nodes.get("session").onclick();
  assert.equal(prepares, 1);
  assert.equal(submissions, 1);
  assert.equal(observations, 1);
  assert.equal(storage.getItem("oaath-demo-session-operation-v1"), null);
  assert.match(nodes.get("status").textContent, /included/u);
});
