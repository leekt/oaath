/**
 * Package boundary: the relay entry stays platform-neutral and PostgreSQL stays
 * behind its own subpath.
 *
 * @author taek <leekt216@gmail.com>
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path/posix";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as server from "../src/index.js";
import * as postgres from "../src/postgres.js";

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

  it("keeps every node and driver import out of the relay entry graph", async () => {
    const root = fileURLToPath(new URL("../src/", import.meta.url));
    const seen = new Set<string>();
    const queue = ["index.ts"];
    while (queue.length > 0) {
      const specifier = queue.pop();
      if (specifier === undefined || seen.has(specifier)) continue;
      seen.add(specifier);
      const source = await readFile(`${root}${specifier}`, "utf8");
      for (const match of source.matchAll(/from "([^"]+)"/gu)) {
        const target = match[1];
        if (target === undefined) continue;
        expect(target.startsWith("node:")).toBe(false);
        expect(target).not.toBe("pg");
        if (!target.startsWith(".")) continue;
        queue.push(join(dirname(specifier), target.replace(/\.js$/u, ".ts")));
      }
    }
    expect(seen.size).toBeGreaterThan(10);
    expect(seen.has("store/postgres/store.ts")).toBe(false);
  });
});
