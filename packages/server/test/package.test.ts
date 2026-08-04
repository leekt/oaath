/**
 * Package boundary: the relay entry and the experimental `./native` preview stay
 * platform-neutral, PostgreSQL stays behind its own subpath, and the
 * experimental `./apns` preview may reach Node crypto and HTTP/2 but never the
 * driver.
 *
 * @author taek <leekt216@gmail.com>
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path/posix";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as apns from "../src/apns.js";
import * as server from "../src/index.js";
import * as native from "../src/native.js";
import * as postgres from "../src/postgres.js";

const SOURCE_ROOT = fileURLToPath(new URL("../src/", import.meta.url));

interface EntryGraph {
  /** Every relative module reachable from the entry. */
  readonly modules: ReadonlySet<string>;
  /** Every non-relative specifier the graph imports. */
  readonly external: ReadonlySet<string>;
}

async function entryGraph(entry: string): Promise<EntryGraph> {
  const modules = new Set<string>();
  const external = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const specifier = queue.pop();
    if (specifier === undefined || modules.has(specifier)) continue;
    modules.add(specifier);
    const source = await readFile(`${SOURCE_ROOT}${specifier}`, "utf8");
    for (const match of source.matchAll(/from "([^"]+)"/gu)) {
      const target = match[1];
      if (target === undefined) continue;
      if (!target.startsWith(".")) {
        external.add(target);
        continue;
      }
      queue.push(join(dirname(specifier), target.replace(/\.js$/u, ".ts")));
    }
  }
  return { modules, external };
}

describe("package boundary", () => {
  it("exports only the accepted relay owners", () => {
    expect(Object.keys(server).sort()).toEqual([
      "OAATH_AUTHORIZATION_CODE_RECORD_VERSION",
      "OAATH_AUTHORIZATION_DECISION_RECORD_VERSION",
      "OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION",
      "OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION",
      "OaathRelayError",
      "REDACTED",
      "RELAY_ERROR_STATUS",
      "claimEncryptedArtifact",
      "consumeAuthorizationCode",
      "createAuthorizationRequest",
      "createMemoryRelayStore",
      "createRelayHandler",
      "fetchAuthorizationRequest",
      "isCodeChallengeS256",
      "openArtifact",
      "redactForLog",
      "redactUrl",
      "resumeAuthorization",
      "sealArtifact",
      "submitAuthorizationDecision",
      "verifyPkceS256",
    ]);
  });

  it("exports only the PostgreSQL owners from the postgres subpath", () => {
    expect(Object.keys(postgres).sort()).toEqual([
      "OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS",
      "OAATH_RELAY_POSTGRES_SCHEMA_VERSION",
      "createPostgresRelaySchema",
      "createPostgresRelayStore",
    ]);
  });

  it("exports only the experimental phone-approval preview owners", () => {
    expect(Object.keys(native).sort()).toEqual([
      "NATIVE_DISPLAY_PAYLOAD_LENGTH",
      "OAATH_NATIVE_PROJECTION_VERSION",
      "projectOwnerPhoneRequest",
      "submitOwnerPhoneDecision",
    ]);
  });

  it("exports only the experimental APNs preview owners", () => {
    expect(Object.keys(apns).sort()).toEqual([
      "APNS_BODY_LOC_KEY",
      "APNS_PAYLOAD_MAX_BYTES",
      "APNS_RETRY_BACKOFF_MS",
      "APNS_TITLE_LOC_KEY",
      "APNS_TOKEN_MAX_REUSE_MS",
      "APNS_TOKEN_MIN_REUSE_MS",
      "OAATH_APNS_DELIVERY_RECORD_VERSION",
      "OAATH_APNS_PAYLOAD_VERSION",
      "createApnsSender",
      "createMemoryApnsOutbox",
      "parseApnsDeliveryRecord",
      "sendApnsNotification",
    ]);
  });

  it("keeps every node and driver import out of the relay entry graph", async () => {
    const graph = await entryGraph("index.ts");
    expect([...graph.external].filter((target) => target.startsWith("node:"))).toEqual([]);
    expect(graph.external.has("pg")).toBe(false);
    expect(graph.modules.size).toBeGreaterThan(10);
    expect(graph.modules.has("store/postgres/store.ts")).toBe(false);
  });

  it("keeps the experimental native preview platform-neutral", async () => {
    const graph = await entryGraph("native.ts");
    expect([...graph.external].filter((target) => target.startsWith("node:"))).toEqual([]);
    expect(graph.external.has("pg")).toBe(false);
    expect(graph.modules.has("store/postgres/store.ts")).toBe(false);
    // The preview reuses the relay's decision owner instead of adding one.
    expect(graph.modules.has("authorization/decision.ts")).toBe(true);
  });

  it("limits the experimental apns preview to node crypto and http2", async () => {
    const graph = await entryGraph("apns.ts");
    for (const target of graph.external) {
      if (!target.startsWith("node:")) continue;
      expect(["node:crypto", "node:http2"]).toContain(target);
    }
    expect(graph.external.has("pg")).toBe(false);
    expect(graph.modules.has("store/postgres/store.ts")).toBe(false);
  });
});
