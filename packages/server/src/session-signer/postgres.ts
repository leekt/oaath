import type { Pool } from "pg";
import {
  captureSignerBinding,
  type SessionSignerBinding,
  SessionSignerError,
  type SessionSignerRegistry,
  signerIdentityKey,
} from "./registry.js";

/** Creates the current schema; deployment owns provisioning and pool lifetime. */
export async function createPostgresSessionSignerSchema(pool: Pick<Pool, "query">): Promise<void> {
  await pool.query(
    `CREATE TABLE oaath_session_signers_v1 (identity text PRIMARY KEY, binding jsonb NOT NULL)`,
  );
}

export function createPostgresSessionSignerRegistry({
  pool,
}: {
  readonly pool: Pool;
}): SessionSignerRegistry {
  return Object.freeze({
    async read(identity: string) {
      try {
        const result = await pool.query(
          "SELECT binding FROM oaath_session_signers_v1 WHERE identity = $1",
          [identity],
        );
        return result.rows[0]?.binding ?? null;
      } catch {
        throw new SessionSignerError("session_signer_registry_unavailable");
      }
    },
    async create(identity: string, produce: () => Promise<Readonly<SessionSignerBinding>>) {
      const client = await pool.connect().catch(() => {
        throw new SessionSignerError("session_signer_registry_unavailable");
      });
      try {
        await client.query("BEGIN");
        // Transaction-scoped locking covers absent rows across processes.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [identity]);
        const result = await client.query(
          "SELECT binding FROM oaath_session_signers_v1 WHERE identity = $1",
          [identity],
        );
        let binding: unknown = result.rows[0]?.binding;
        if (result.rows.length === 0) {
          const created = captureSignerBinding(await produce());
          if (signerIdentityKey(created.identity) !== identity)
            throw new SessionSignerError("session_signer_binding_mismatch");
          await client.query(
            "INSERT INTO oaath_session_signers_v1 (identity, binding) VALUES ($1, $2::jsonb)",
            [identity, JSON.stringify(created)],
          );
          binding = created;
        }
        await client.query("COMMIT");
        return binding;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        if (error instanceof SessionSignerError) throw error;
        throw new SessionSignerError("session_signer_registry_unavailable");
      } finally {
        client.release();
      }
    },
  });
}
