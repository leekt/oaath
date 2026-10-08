/**
 * PostgreSQL: the service's only dependency and the owner of every durable
 * fact. One current schema version; an older or foreign schema is refused and
 * must be dropped and recreated (there are no migrations).
 *
 * @author taek <leekt216@gmail.com>
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import pg from "pg";

export const AUTOMATION_SCHEMA_VERSION = "oaath.automation-postgres-schema/v2" as const;

export type Pool = pg.Pool;
export type Client = pg.PoolClient;

const RUN_STATUSES =
  "'due','claimed','prepared','submitted','observed','finalized','failed','skipped'";
const PLAN_STATUSES =
  "'draft','awaiting_consent','authorized','active','paused','cancelling','cancelled','completed','expired','failed'";

const SCHEMA = `
CREATE TABLE automation_schema (version text PRIMARY KEY);
CREATE TABLE automation_applications (
  app_id text PRIMARY KEY,
  key_scope text NOT NULL CHECK (key_scope IN ('user','application'))
);
CREATE TABLE automation_sessions (
  token_hash text PRIMARY KEY, app_id text NOT NULL, user_id text NOT NULL,
  account text NOT NULL, expires_at bigint NOT NULL
);
CREATE TABLE automation_signers (
  scope_id text PRIMARY KEY, address text NOT NULL, device_id text NOT NULL,
  sealed jsonb NOT NULL, created_at bigint NOT NULL
);
CREATE TABLE automation_plans (
  id text PRIMARY KEY, app_id text NOT NULL, user_id text NOT NULL, account text NOT NULL,
  key_scope text NOT NULL CHECK (key_scope IN ('user','application')),
  automation_id text NOT NULL, definition jsonb NOT NULL, terms jsonb NOT NULL, plan_hash text NOT NULL,
  creation_key text NOT NULL, input_digest text NOT NULL,
  status text NOT NULL CHECK (status IN (${PLAN_STATUSES})),
  revision bigint NOT NULL DEFAULT 0,
  signer_scope text, signer text, permission jsonb,
  oauth_state text UNIQUE, oauth jsonb, return_to text, next_consent_at bigint,
  grant_id text UNIQUE, binding jsonb,
  next_slot integer NOT NULL DEFAULT 0, next_at bigint NOT NULL,
  created_at bigint NOT NULL, diagnostic text,
  UNIQUE (app_id, account, creation_key)
);
CREATE INDEX automation_plans_due ON automation_plans (next_at, id) WHERE status IN ('active','paused');
CREATE INDEX automation_plans_user ON automation_plans (app_id, user_id, created_at, id);
CREATE INDEX automation_plans_consent ON automation_plans (next_consent_at) WHERE next_consent_at IS NOT NULL;
CREATE TABLE automation_runs (
  plan_id text NOT NULL REFERENCES automation_plans(id), run_key text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('setup','occurrence','cancel')), slot integer,
  lane integer NOT NULL CHECK (lane BETWEEN 0 AND 65535),
  scheduled_at bigint NOT NULL, closes_at bigint,
  status text NOT NULL CHECK (status IN (${RUN_STATUSES})),
  calls jsonb, op_hash text, op_nonce text, transaction_hash text, evidence jsonb, reason text,
  attempts integer NOT NULL DEFAULT 0, observations integer NOT NULL DEFAULT 0,
  generation bigint NOT NULL DEFAULT 0, lease_until bigint NOT NULL DEFAULT 0, lease_owner text,
  next_attempt_at bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (plan_id, run_key)
);
CREATE INDEX automation_runs_open ON automation_runs (next_attempt_at, plan_id)
  WHERE status IN ('due','claimed','prepared','submitted','observed');
CREATE UNIQUE INDEX automation_runs_lane_open ON automation_runs (plan_id, lane)
  WHERE status IN ('due','claimed','prepared','submitted','observed');
CREATE TABLE automation_grants (
  grant_id text PRIMARY KEY, store_revision bigint NOT NULL, record text NOT NULL
);
CREATE TABLE automation_operations (
  grant_id text NOT NULL, chain_id bigint NOT NULL, kind text NOT NULL, lane bigint NOT NULL,
  store_revision bigint NOT NULL, record text NOT NULL,
  PRIMARY KEY (grant_id, chain_id, kind, lane)
);
CREATE TABLE automation_operation_archive (
  grant_id text NOT NULL, chain_id bigint NOT NULL, kind text NOT NULL, lane bigint NOT NULL,
  user_operation_hash text NOT NULL, record text NOT NULL,
  PRIMARY KEY (grant_id, chain_id, kind, lane, user_operation_hash)
);
CREATE TABLE automation_contexts (binding_id text PRIMARY KEY, record text NOT NULL);
`;

export class StorageError extends Error {
  readonly code: "schema_unsupported" | "storage_unavailable";
  constructor(code: StorageError["code"]) {
    super(code);
    this.name = "StorageError";
    this.code = code;
  }
}

const INT8 = 20;
/** Every bigint column here holds Unix seconds or small counters: safe integers. */
const types = {
  getTypeParser: ((oid: number, format?: "text" | "binary") =>
    oid === INT8 ? (value: string) => Number(value) : pg.types.getTypeParser(oid, format)) as never,
};

export function createPool(databaseUrl: string): Pool {
  return new pg.Pool({
    connectionString: databaseUrl,
    max: 12,
    connectionTimeoutMillis: 5000,
    types,
  });
}

/**
 * Creates the schema in an empty database, or verifies the current one.
 * Serialized by an advisory lock so replicas may start together.
 */
export async function initializeSchema(pool: Pool): Promise<void> {
  await transaction(pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(74639202)");
    const present = await client.query(
      "SELECT to_regclass('automation_schema') AS name, (SELECT count(*) FROM pg_tables WHERE tablename LIKE 'automation\\_%') AS tables",
    );
    if (present.rows[0].name === null) {
      if (Number(present.rows[0].tables) > 0) throw new StorageError("schema_unsupported");
      await client.query(SCHEMA);
      await client.query("INSERT INTO automation_schema(version) VALUES ($1)", [
        AUTOMATION_SCHEMA_VERSION,
      ]);
      return;
    }
    const version = await client.query("SELECT version FROM automation_schema");
    if (version.rows.length !== 1 || version.rows[0].version !== AUTOMATION_SCHEMA_VERSION)
      throw new StorageError("schema_unsupported");
  });
}

export async function transaction<T>(pool: Pool, work: (client: Client) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export const now = (): number => Math.floor(Date.now() / 1000);

export interface Sealed {
  readonly version: "oaath.automation-sealed/v1";
  readonly iv: string;
  readonly data: string;
  readonly tag: string;
}

/** AES-256-GCM with the record's own identity as additional data. */
export function seal(key: Buffer, value: unknown, aad: string): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return {
    version: "oaath.automation-sealed/v1",
    iv: iv.toString("hex"),
    data: data.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
  };
}

export class CustodyError extends Error {
  readonly code = "custody_unavailable" as const;
  constructor() {
    super("custody_unavailable");
    this.name = "CustodyError";
  }
}

/** Unreadable, foreign or tampered sealed data fails closed; it is never treated as absent. */
export function open<T>(key: Buffer, value: unknown, aad: string): T {
  const sealed = value as Partial<Sealed> | null;
  if (sealed?.version !== "oaath.automation-sealed/v1") throw new CustodyError();
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.iv ?? "", "hex"));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(sealed.tag ?? "", "hex"));
    return JSON.parse(
      Buffer.concat([
        decipher.update(Buffer.from(sealed.data ?? "", "hex")),
        decipher.final(),
      ]).toString(),
    ) as T;
  } catch {
    throw new CustodyError();
  }
}
