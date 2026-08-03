/**
 * In-memory relay store implementing the same transaction contract as
 * PostgreSQL. It is durable only for the life of the process: use it for local
 * development and tests, never for a deployment that must survive a restart.
 *
 * ponytail: one process-wide writer lock stands in for row locks. It is strictly
 * stronger than `SELECT ... FOR UPDATE`, so one-shot semantics are identical;
 * swap in per-row locks only if a single-process relay ever needs throughput.
 *
 * @author taek <leekt216@gmail.com>
 */

import { relayFailure } from "../relay/errors.js";
import type { RelayStore, RelayTransaction } from "./interface.js";
import {
  type AuthorizationCodeRecord,
  type AuthorizationDecisionRecord,
  type AuthorizationRequestRecord,
  type EncryptedArtifactRecord,
  parseAuthorizationCodeRecord,
  parseAuthorizationDecisionRecord,
  parseAuthorizationRequestRecord,
  parseEncryptedArtifactRecord,
} from "./records.js";

interface Tables {
  readonly requests: Map<string, unknown>;
  readonly decisions: Map<string, unknown>;
  readonly codes: Map<string, unknown>;
  readonly artifacts: Map<string, unknown>;
}

function emptyTables(): Tables {
  return {
    requests: new Map(),
    decisions: new Map(),
    codes: new Map(),
    artifacts: new Map(),
  };
}

function copyTables(tables: Tables): Tables {
  return {
    requests: new Map(tables.requests),
    decisions: new Map(tables.decisions),
    codes: new Map(tables.codes),
    artifacts: new Map(tables.artifacts),
  };
}

function insert(table: Map<string, unknown>, key: string, record: unknown): boolean {
  if (table.has(key)) return false;
  table.set(key, record);
  return true;
}

function read<Value>(
  table: Map<string, unknown>,
  key: string,
  parse: (value: unknown) => Value,
): Value | undefined {
  const stored = table.get(key);
  // Durable reads are re-validated here exactly as the SQL store validates rows.
  return stored === undefined ? undefined : parse(stored);
}

export function createMemoryRelayStore(): RelayStore {
  let committed = emptyTables();
  let closed = false;
  let tail: Promise<void> = Promise.resolve();

  async function acquire(): Promise<() => void> {
    const prior = tail;
    let release = (): void => {};
    tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    return release;
  }

  return {
    async begin(): Promise<RelayTransaction> {
      if (closed) relayFailure("relay_store_unavailable", "memory relay store is closed");
      const release = await acquire();
      const staged = copyTables(committed);
      let settled = false;

      const open = (): Tables => {
        if (settled) relayFailure("relay_internal", "relay transaction already settled");
        return staged;
      };
      const settle = (apply: boolean): void => {
        if (settled) relayFailure("relay_internal", "relay transaction already settled");
        settled = true;
        if (apply) committed = staged;
        release();
      };

      return {
        async lockAuthorizationRequest(requestId) {
          return read(open().requests, requestId, parseAuthorizationRequestRecord);
        },
        async insertAuthorizationRequest(record: AuthorizationRequestRecord) {
          return insert(open().requests, record.requestId, record);
        },
        async lockAuthorizationDecision(requestId) {
          return read(open().decisions, requestId, parseAuthorizationDecisionRecord);
        },
        async insertAuthorizationDecision(record: AuthorizationDecisionRecord) {
          return insert(open().decisions, record.requestId, record);
        },
        async lockAuthorizationCode(codeHash) {
          return read(open().codes, codeHash, parseAuthorizationCodeRecord);
        },
        async insertAuthorizationCode(record: AuthorizationCodeRecord) {
          return insert(open().codes, record.codeHash, record);
        },
        async consumeAuthorizationCode(codeHash, consumedAt) {
          const codes = open().codes;
          const record = read(codes, codeHash, parseAuthorizationCodeRecord);
          if (!record || record.consumedAt !== null) return false;
          codes.set(codeHash, Object.freeze({ ...record, consumedAt }));
          return true;
        },
        async lockEncryptedArtifact(artifactId) {
          return read(open().artifacts, artifactId, parseEncryptedArtifactRecord);
        },
        async insertEncryptedArtifact(record: EncryptedArtifactRecord) {
          return insert(open().artifacts, record.artifactId, record);
        },
        async claimEncryptedArtifact(artifactId, claimedAt) {
          const artifacts = open().artifacts;
          const record = read(artifacts, artifactId, parseEncryptedArtifactRecord);
          if (!record || record.claimedAt !== null) return false;
          artifacts.set(artifactId, Object.freeze({ ...record, claimedAt }));
          return true;
        },
        async commit() {
          settle(true);
        },
        async rollback() {
          if (!settled) settle(false);
        },
      };
    },
    async close(): Promise<void> {
      closed = true;
      committed = emptyTables();
    },
  };
}
