import type { Pool } from "pg";
import { relayFailure } from "../relay/errors.js";
import type { ServiceDirectoryStore } from "./service.js";

/** Creates the current directory schema; existing/older tables are never migrated. */
export async function createPostgresServiceDirectorySchema(
  pool: Pick<Pool, "query">,
): Promise<void> {
  await pool.query(`CREATE TABLE oaath_service_directory_v1 (
    directory_id text PRIMARY KEY CHECK (directory_id = 'oaath'),
    revision bigint NOT NULL CHECK (revision >= 1 AND revision <= ${Number.MAX_SAFE_INTEGER}),
    directory jsonb NOT NULL
  )`);
}

/** The deployment owns this pool's connection policy and shutdown. */
export function createPostgresServiceDirectoryStore(options: {
  readonly pool: Pool;
}): ServiceDirectoryStore {
  const { pool } = options;
  return {
    async read() {
      try {
        const result = await pool.query(
          "SELECT revision, directory FROM oaath_service_directory_v1 WHERE directory_id = 'oaath'",
        );
        const row = result.rows[0];
        return row === undefined
          ? null
          : { revision: Number(row.revision), directory: row.directory };
      } catch {
        return relayFailure("relay_store_unavailable", "directory store is unavailable");
      }
    },
    async compareAndSwap(expectedRevision, directory) {
      const serialized = JSON.stringify(directory);
      try {
        const result =
          expectedRevision === null
            ? await pool.query(
                "INSERT INTO oaath_service_directory_v1 (directory_id, revision, directory) VALUES ('oaath', 1, $1::jsonb) ON CONFLICT DO NOTHING RETURNING revision",
                [serialized],
              )
            : await pool.query(
                "UPDATE oaath_service_directory_v1 SET revision = revision + 1, directory = $1::jsonb WHERE directory_id = 'oaath' AND revision = $2 RETURNING revision",
                [serialized, expectedRevision],
              );
        return result.rows.length === 1;
      } catch {
        return relayFailure("relay_state_ambiguous", "directory write outcome is unknown");
      }
    },
  };
}
