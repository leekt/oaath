import type { Pool } from "pg";
import { relayFailure } from "../relay/errors.js";
import type { OwnerDeviceCredentialStore } from "./authentication.js";

/** Provision once in a new schema. Older credential schemas are never migrated. */
export async function createPostgresOwnerDeviceCredentialSchema(
  pool: Pick<Pool, "query">,
): Promise<void> {
  await pool.query(`CREATE TABLE oaath_owner_device_credentials_v1 (
    credential_hash text PRIMARY KEY,
    version text NOT NULL CHECK (version = 'oaath.owner-device-credential/v1'),
    workspace_id text NOT NULL,
    owner_device_id text NOT NULL,
    subject text NOT NULL,
    revoked boolean NOT NULL
  )`);
}

/** Deployment owns the pool. Every write is one statement and is never retried. */
export function createPostgresOwnerDeviceCredentialStore(options: {
  readonly pool: Pool;
}): OwnerDeviceCredentialStore {
  const { pool } = options;
  return {
    async read(hash) {
      try {
        const result = await pool.query(
          `SELECT version, credential_hash AS "credentialHash",
          workspace_id AS "workspaceId", owner_device_id AS "ownerDeviceId", subject, revoked
          FROM oaath_owner_device_credentials_v1 WHERE credential_hash = $1`,
          [hash],
        );
        return result.rows[0] ?? null;
      } catch {
        return relayFailure(
          "relay_store_unavailable",
          "owner device credential store is unavailable",
        );
      }
    },
    async insert(record) {
      try {
        const result = await pool.query(
          `INSERT INTO oaath_owner_device_credentials_v1
          (credential_hash, version, workspace_id, owner_device_id, subject, revoked)
          VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING credential_hash`,
          [
            record.credentialHash,
            record.version,
            record.workspaceId,
            record.ownerDeviceId,
            record.subject,
            record.revoked,
          ],
        );
        return result.rows.length === 1;
      } catch {
        return relayFailure(
          "relay_state_ambiguous",
          "owner device credential write outcome is unknown",
        );
      }
    },
    async revoke(device) {
      try {
        await pool.query(
          `UPDATE oaath_owner_device_credentials_v1 SET revoked = TRUE
          WHERE workspace_id = $1 AND owner_device_id = $2 AND revoked = FALSE`,
          [device.workspaceId, device.ownerDeviceId],
        );
      } catch {
        return relayFailure(
          "relay_state_ambiguous",
          "owner device credential revocation outcome is unknown",
        );
      }
    },
  };
}
