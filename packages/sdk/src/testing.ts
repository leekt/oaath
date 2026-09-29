/**
 * `@oaath/sdk/testing` — the deterministic in-memory store set. Never a
 * production dependency: nothing here survives a reload, which is the point.
 * `createOAAth` options take `stores: { kind: "memory" }` instead.
 *
 * @author taek <leekt216@gmail.com>
 */
export { createMemoryStores } from "./client/stores.js";
