import assert from "node:assert/strict";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";

const { outputFiles } = await build({
  entryPoints: [new URL("./worker.js", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "iife",
  plugins: [
    {
      name: "worker-capabilities",
      setup(builder) {
        builder.onResolve({ filter: /^@oaath\/sdk(?:\/.*)?$/ }, ({ path }) => ({
          path,
          namespace: "test",
        }));
        builder.onLoad({ filter: /.*/, namespace: "test" }, ({ path }) => ({
          contents: path.endsWith("/cetane")
            ? "export const oaathProvider = () => { throw new Error('unexpected provider'); };"
            : "export const createOAAth = globalThis.createOAAth;",
        }));
      },
    },
  ],
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function worker() {
  let listener;
  const opened = [];
  const connected = [];
  const configured = { issuer: "https://issuer-a.test", chain: 1 };
  const context = {
    URL,
    chrome: {
      storage: {
        local: {
          // Settings read with defaults; a registered client is already stored.
          get: async (keys) =>
            typeof keys === "string" ? { [keys]: "client-1" } : { ...keys, ...configured },
        },
      },
      identity: {
        getRedirectURL: (path) => `https://test.chromiumapp.org/${path}`,
        launchWebAuthFlow: async () => {
          throw new Error("unexpected portal");
        },
      },
      tabs: { onRemoved: { addListener() {} } },
      runtime: {
        id: "test",
        onMessage: {
          addListener(value) {
            listener = value;
          },
        },
      },
    },
    // Each realm owns one named database, released by its close.
    createOAAth: ({ origin, approvals, stores }) => {
      const url = approvals.issuer;
      const database = { name: stores.name, closed: 0 };
      opened.push(database);
      const own = [];
      return {
        close: async () => {
          for (const connection of own) await connection.close();
          database.closed++;
        },
        connect: async () => {
          const ready = deferred();
          const permission = deferred();
          const connection = {
            origin,
            url,
            ready,
            permission,
            closed: 0,
            requests: 0,
            resume: async () => null,
            redeemPending: async () => null,
            close: async () => {
              connection.closed++;
            },
            requestPermission: async () => {
              connection.requests++;
              return permission.promise;
            },
          };
          connected.push(connection);
          await ready.promise;
          own.push(connection);
          return connection;
        },
      };
    },
  };
  runInNewContext(outputFiles[0].text, context);
  const message = (command, origin = "https://app.test") =>
    new Promise((resolve) => {
      listener(
        { type: "popup", command, origin, scope: { target: "0x01", selector: "0x02" } },
        { origin: "chrome-extension://test" },
        resolve,
      );
    });
  return { message, opened, connected, configured };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));
const granted = { state: "active", account: async () => "0xaccount" };

test("concurrent first pair messages share a connection and permission slot", async () => {
  const realm = worker();
  const first = realm.message("pair");
  const second = realm.message("pair");
  await tick();
  assert.equal(realm.opened.length, 1);
  assert.equal(realm.connected.length, 1);
  realm.connected[0].ready.resolve();
  await tick();
  assert.equal(realm.connected[0].requests, 1);
  assert.equal((await second).error.code, -32002);
  realm.connected[0].permission.resolve(granted);
  assert.equal((await first).ok, true);
  // Chains are fixed per realm: a chain change opens a new realm on the same database.
  realm.configured.chain = 10;
  const changed = realm.message("status");
  await tick();
  assert.equal(realm.connected.length, 2);
  assert.equal(realm.opened[1].name, realm.opened[0].name);
  realm.connected[1].ready.resolve();
  assert.equal((await changed).result.chain, 10);
});

test("failed initialization closes its database and permits a fresh retry", async () => {
  const realm = worker();
  const failed = realm.message("status");
  await tick();
  realm.connected[0].ready.reject(new Error("connection unavailable"));
  assert.equal((await failed).ok, false);
  assert.equal(realm.opened[0].closed, 1);
  const retry = realm.message("status");
  await tick();
  assert.equal(realm.connected.length, 2);
  realm.connected[1].ready.resolve();
  assert.equal((await retry).ok, true);
});

test("an issuer change during initialization closes the old realm once", async () => {
  const realm = worker();
  const old = realm.message("status");
  await tick();
  realm.configured.issuer = "https://issuer-b.test";
  const first = realm.message("status");
  const second = realm.message("status");
  await tick();
  assert.equal(realm.connected.length, 1);
  realm.connected[0].ready.resolve();
  await old;
  await tick();
  assert.equal(realm.connected[0].closed, 1);
  assert.equal(realm.opened[0].closed, 1);
  assert.equal(realm.connected.length, 2);
  realm.connected[1].ready.resolve();
  assert.equal((await first).result.issuer, "https://issuer-b.test");
  assert.equal((await second).result.issuer, "https://issuer-b.test");
});

test("distinct page origins retain separate connections", async () => {
  const realm = worker();
  const first = realm.message("status");
  const second = realm.message("status", "https://other.test");
  await tick();
  assert.equal(realm.connected.length, 2);
  assert.notEqual(realm.opened[0].name, realm.opened[1].name);
  for (const connection of realm.connected) connection.ready.resolve();
  assert.equal((await first).ok, true);
  assert.equal((await second).ok, true);
});
