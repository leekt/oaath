import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";

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
      "chain",
      "observe",
      "revoke",
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

test("page has pairing, connection, consent, job observation and revocation actions", () => {
  const page = readFileSync(new URL("./page.html", import.meta.url), "utf8");
  const buttonIds = [...page.matchAll(/<button[^>]+id="([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(buttonIds, ["pair", "unlock", "permission", "session", "observe", "revoke"]);
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

// Run the complete page controller in an isolated browser realm. Only its SDK
// port is replaced: these tests prove UI orchestration, not chain execution.
const controller = await build({
  entryPoints: [new URL("./browser.js", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "iife",
  plugins: [
    {
      name: "page-sdk-port",
      setup(builder) {
        // esbuild uses Go regular expressions, which do not support JS's u flag.
        builder.onResolve({ filter: /^@oaath\/sdk$/ }, () => ({
          path: "sdk",
          namespace: "page-sdk-port",
        }));
        builder.onLoad({ filter: /.*/, namespace: "page-sdk-port" }, () => ({
          contents: "export const createOAAth = globalThis.createOAAth;",
        }));
      },
    },
  ],
});

async function pageRealm({ storage, createOAAth }) {
  const nodes = new Map();
  const element = (id = "") => ({
    id,
    textContent: "",
    value: "",
    disabled: true,
    hidden: false,
    attributes: new Map(),
    setAttribute(name, value) {
      this.attributes.set(name, value);
    },
    removeAttribute(name) {
      this.attributes.delete(name);
    },
    replaceChildren() {},
    querySelector() {
      return null;
    },
  });
  const html = readFileSync(new URL("./page.html", import.meta.url), "utf8");
  for (const [, id] of html.matchAll(/\bid="([^"]+)"/gu)) nodes.set(id, element(id));
  runInNewContext(controller.outputFiles[0].text, {
    createOAAth,
    document: {
      getElementById: (id) => nodes.get(id),
      createElement: () => element(),
      querySelector: () => null,
    },
    localStorage: storage,
    location: { origin: "http://127.0.0.1:8787" },
    fetch: async () =>
      jsonResponse({ account: "phone-owned-account", chains: [{ chainId: 31337, name: "Local" }] }),
    Headers,
    Request,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  });
  // Buffered responses resolve in microtasks; no network or timer is polled.
  await new Promise(setImmediate);
  return nodes;
}

const savedJobKey = "oaath.phone-demo-operation/v1";
const savedJob = { version: savedJobKey, chain: 31337, id: `0x${"ab".repeat(32)}` };

for (const state of ["revoked", "expired"])
  test(`${state} permission keeps its saved job recoverable before replacement`, async () => {
    const storage = new MemoryStorage();
    storage.setItem(savedJobKey, JSON.stringify(savedJob));
    let current = "old";
    let permissions = 0;
    let sends = 0;
    let outcome = "pending";
    const observedBy = [];
    const createOAAth = () => ({
      async connect() {
        return {
          async resume() {
            const owner = current;
            return {
              state: owner === "old" ? state : "active",
              async sendCalls() {
                sends += 1;
                throw new Error("this scenario must only observe");
              },
              async getOperation({ chain, id }) {
                observedBy.push(owner);
                assert.equal(chain, savedJob.chain);
                assert.equal(id, savedJob.id);
                if (owner !== "old" || outcome === "missing") return null;
                return {
                  id,
                  async observe() {
                    if (outcome === "unavailable") throw new Error("observation unavailable");
                    return {
                      status: outcome,
                      outcome: "success",
                      transactionHash: `0x${"cd".repeat(32)}`,
                    };
                  },
                };
              },
            };
          },
          async requestPermission() {
            permissions += 1;
            current = "new";
            return { state: "active" };
          },
        };
      },
    });

    let nodes = await pageRealm({ storage, createOAAth });
    assert.equal(nodes.get("permission").disabled, true);
    assert.equal(nodes.get("permission-recovery").hidden, false);
    // The action guards its own state too, even if invoked from an old view.
    await nodes.get("permission").onclick();
    assert.equal(permissions, 0);

    for (const next of ["pending", "unavailable", "missing"]) {
      outcome = next;
      nodes = await pageRealm({ storage, createOAAth });
      await nodes.get("observe").onclick();
      assert.equal(storage.getItem(savedJobKey), JSON.stringify(savedJob));
      assert.equal(nodes.get("permission").disabled, true);
      assert.equal(permissions, 0);
    }

    outcome = state === "revoked" ? "finalized" : "superseded";
    nodes = await pageRealm({ storage, createOAAth });
    await nodes.get("observe").onclick();
    assert.equal(storage.getItem(savedJobKey), null);
    assert.equal(nodes.get("permission").disabled, false);
    assert.equal(nodes.get("permission-recovery").hidden, true);
    await nodes.get("permission").onclick();
    assert.equal(permissions, 1);
    assert.deepEqual(observedBy, ["old", "old", "old", "old"]);
    assert.equal(sends, 0);
  });

test("unreadable saved job cannot be orphaned by a new permission", async () => {
  const storage = new MemoryStorage();
  storage.setItem(savedJobKey, "unreadable");
  let permissions = 0;
  const nodes = await pageRealm({
    storage,
    createOAAth: () => ({
      async connect() {
        return {
          resume: async () => ({ state: "revoked" }),
          async requestPermission() {
            permissions += 1;
            return { state: "active" };
          },
        };
      },
    }),
  });
  assert.equal(nodes.get("permission").disabled, true);
  await nodes.get("permission").onclick();
  assert.equal(permissions, 0);
  assert.equal(storage.getItem(savedJobKey), "unreadable");
});
