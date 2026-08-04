import assert from "node:assert/strict";
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
}

const jsonResponse = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

function installDocument() {
  const nodes = new Map(
    ["status", "account", "unlock", "permission", "session", "owner"].map((id) => [
      id,
      { id, textContent: "", onclick: null },
    ]),
  );
  globalThis.document = { getElementById: (id) => nodes.get(id) };
  return nodes;
}

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
