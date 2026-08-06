import { DatabaseSync } from "node:sqlite";
import {
  GrantStore,
  type GrantStoreAdapter,
  OaathStoreError,
  OperationStore,
  type OperationStoreAdapter,
  type StoreRecord,
} from "@oaath/sdk/advanced";

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const SQLITE_SCHEMA_VERSION = "oaath.sqlite-test-store/v1";

const METADATA_SCHEMA = `
  CREATE TABLE oaath_test_store_schema_v1 (
    schema_id TEXT PRIMARY KEY CHECK (schema_id = 'oaath'),
    version TEXT NOT NULL
  ) STRICT, WITHOUT ROWID
`;

const GRANT_SCHEMA = `
  CREATE TABLE oaath_test_grant_store_v1 (
    grant_id TEXT PRIMARY KEY,
    record_version TEXT NOT NULL,
    store_revision INTEGER NOT NULL CHECK (store_revision >= 0 AND store_revision <= ${MAX_SAFE_INTEGER}),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0 AND updated_at <= ${MAX_SAFE_INTEGER}),
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID
`;

const OPERATION_SCHEMA = `
  CREATE TABLE oaath_test_operation_store_v1 (
    grant_id TEXT NOT NULL,
    chain_id INTEGER NOT NULL CHECK (chain_id >= 1 AND chain_id <= ${MAX_SAFE_INTEGER}),
    kind TEXT NOT NULL CHECK (kind IN ('execution', 'revocation')),
    record_version TEXT NOT NULL,
    store_revision INTEGER NOT NULL CHECK (store_revision >= 0 AND store_revision <= ${MAX_SAFE_INTEGER}),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0 AND updated_at <= ${MAX_SAFE_INTEGER}),
    payload TEXT NOT NULL,
    PRIMARY KEY (grant_id, chain_id, kind)
  ) STRICT, WITHOUT ROWID
`;

const EXPECTED_SCHEMAS = new Map([
  ["oaath_test_store_schema_v1", METADATA_SCHEMA],
  ["oaath_test_grant_store_v1", GRANT_SCHEMA],
  ["oaath_test_operation_store_v1", OPERATION_SCHEMA],
]);

type StoredRow = Readonly<{
  record_version: string;
  store_revision: number;
  updated_at: number;
  payload: string;
}>;

type SchemaObject = Readonly<{
  type: string;
  name: string;
  sql: string | null;
}>;

function normalizedSql(value: string): string {
  return value.replaceAll(/\s+/gu, " ").trim();
}

function validateSchema(database: DatabaseSync): void {
  const objects = database
    .prepare(`
      SELECT type, name, sql
      FROM sqlite_schema
      WHERE substr(name, 1, 7) <> 'sqlite_'
      ORDER BY type, name
    `)
    .all() as SchemaObject[];
  if (objects.length !== EXPECTED_SCHEMAS.size) {
    throw new OaathStoreError("store_record_invalid", "SQLite test store schema is unsupported");
  }
  for (const object of objects) {
    const expected = EXPECTED_SCHEMAS.get(object.name);
    if (
      object.type !== "table" ||
      object.sql === null ||
      expected === undefined ||
      normalizedSql(object.sql) !== normalizedSql(expected)
    ) {
      throw new OaathStoreError("store_record_invalid", "SQLite test store schema is unsupported");
    }
  }
  const versions = database
    .prepare("SELECT schema_id, version FROM oaath_test_store_schema_v1")
    .all() as Array<{ schema_id: unknown; version: unknown }>;
  if (
    versions.length !== 1 ||
    versions[0]?.schema_id !== "oaath" ||
    versions[0]?.version !== SQLITE_SCHEMA_VERSION
  ) {
    throw new OaathStoreError(
      "store_record_invalid",
      "SQLite test store schema version is unsupported",
    );
  }
}

function initializeOrValidateSchema(database: DatabaseSync): void {
  database.exec("BEGIN IMMEDIATE");
  let transactionOpen = true;
  try {
    const objectCount = database
      .prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE substr(name, 1, 7) <> 'sqlite_'")
      .get() as { count?: unknown } | undefined;
    if (objectCount?.count === 0 || objectCount?.count === 0n) {
      database.exec(METADATA_SCHEMA);
      database.exec(GRANT_SCHEMA);
      database.exec(OPERATION_SCHEMA);
      database
        .prepare("INSERT INTO oaath_test_store_schema_v1 (schema_id, version) VALUES (?, ?)")
        .run("oaath", SQLITE_SCHEMA_VERSION);
    }
    validateSchema(database);
    database.exec("COMMIT");
    transactionOpen = false;
  } catch (error) {
    if (transactionOpen) {
      try {
        database.exec("ROLLBACK");
      } catch {
        // Cleanup is secondary to the canonical schema failure.
      }
    }
    throw error;
  }
}

function openDatabase(filePath: string): DatabaseSync {
  if (typeof filePath !== "string" || filePath.length === 0 || filePath === ":memory:") {
    throw new OaathStoreError("store_input_invalid", "SQLite test store requires a file path");
  }
  let database: DatabaseSync | undefined;
  try {
    database = new DatabaseSync(filePath);
    database.exec("PRAGMA journal_mode = WAL");
    database.exec("PRAGMA busy_timeout = 250");
    initializeOrValidateSchema(database);
    return database;
  } catch (error) {
    try {
      database?.close();
    } catch {
      // Cleanup is secondary to the canonical open failure.
    }
    if (error instanceof OaathStoreError) throw error;
    throw new OaathStoreError("store_unavailable", "SQLite test store could not be opened");
  }
}

function prepareStore<Value>(database: DatabaseSync, prepare: () => Value): Value {
  try {
    return prepare();
  } catch {
    try {
      database.close();
    } catch {
      // Cleanup is secondary to the canonical preparation failure.
    }
    throw new OaathStoreError("store_unavailable", "SQLite test store could not be prepared");
  }
}

function encode(value: unknown): string {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("SQLite test store value is not JSON-safe");
  return encoded;
}

function decode(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    // Preserve malformed durable evidence for the owning root codec to reject.
    return value;
  }
}

function envelope(row: StoredRow | undefined): Readonly<StoreRecord<unknown>> | undefined {
  if (!row) return undefined;
  return Object.freeze({
    version: row.record_version,
    storeRevision: row.store_revision,
    updatedAt: row.updated_at,
    value: decode(row.payload),
  });
}

/** Test-only durable SQLite Grant store. It makes no production durability claim. */
export function createSqliteGrantStore(filePath: string): GrantStore {
  const database = openDatabase(filePath);
  return prepareStore(database, () => {
    const get = database.prepare(`
    SELECT record_version, store_revision, updated_at, payload
    FROM oaath_test_grant_store_v1
    WHERE grant_id = ?
  `);
    const insert = database.prepare(`
    INSERT INTO oaath_test_grant_store_v1 (
      grant_id, record_version, store_revision, updated_at, payload
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (grant_id) DO NOTHING
  `);
    const update = database.prepare(`
    UPDATE oaath_test_grant_store_v1
    SET record_version = ?, store_revision = ?, updated_at = ?, payload = ?
    WHERE grant_id = ? AND store_revision = ?
  `);
    const adapter: GrantStoreAdapter = {
      async get(grantId) {
        return envelope(get.get(grantId) as StoredRow | undefined);
      },
      async compareAndSwap({ grantId, expectedStoreRevision, next }) {
        const payload = encode(next.value);
        const result =
          expectedStoreRevision === null
            ? insert.run(grantId, next.version, next.storeRevision, next.updatedAt, payload)
            : update.run(
                next.version,
                next.storeRevision,
                next.updatedAt,
                payload,
                grantId,
                expectedStoreRevision,
              );
        return Number(result.changes) === 1;
      },
      async close() {
        database.close();
      },
    };
    return new GrantStore(adapter);
  });
}

/** Test-only durable SQLite Operation store. It makes no production durability claim. */
export function createSqliteOperationStore(filePath: string): OperationStore {
  const database = openDatabase(filePath);
  return prepareStore(database, () => {
    const get = database.prepare(`
    SELECT record_version, store_revision, updated_at, payload
    FROM oaath_test_operation_store_v1
    WHERE grant_id = ? AND chain_id = ? AND kind = ?
  `);
    const insert = database.prepare(`
    INSERT INTO oaath_test_operation_store_v1 (
      grant_id, chain_id, kind, record_version, store_revision, updated_at, payload
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (grant_id, chain_id, kind) DO NOTHING
  `);
    const update = database.prepare(`
    UPDATE oaath_test_operation_store_v1
    SET record_version = ?, store_revision = ?, updated_at = ?, payload = ?
    WHERE grant_id = ? AND chain_id = ? AND kind = ? AND store_revision = ?
  `);
    const adapter: OperationStoreAdapter = {
      async get(key) {
        return envelope(get.get(key.grantId, key.chainId, key.kind) as StoredRow | undefined);
      },
      async compareAndSwap({ key, expectedStoreRevision, next }) {
        const payload = encode(next.value);
        const result =
          expectedStoreRevision === null
            ? insert.run(
                key.grantId,
                key.chainId,
                key.kind,
                next.version,
                next.storeRevision,
                next.updatedAt,
                payload,
              )
            : update.run(
                next.version,
                next.storeRevision,
                next.updatedAt,
                payload,
                key.grantId,
                key.chainId,
                key.kind,
                expectedStoreRevision,
              );
        return Number(result.changes) === 1;
      },
      async close() {
        database.close();
      },
    };
    return new OperationStore(adapter);
  });
}
