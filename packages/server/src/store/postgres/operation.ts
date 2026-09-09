/** PostgreSQL persistence for the existing SDK OperationStore; no second state machine. */
import type { OperationStoreAdapter, OperationStoreKey } from "@oaath/sdk/advanced";
import type { Pool } from "pg";
import { relayFailure } from "../../relay/errors.js";
import type { RelaySchemaExecutor } from "./schema.js";

/** Current schema; obsolete state is recreated, never migrated. Records remain SDK-owned v2. */
export async function createPostgresOperationSchema(executor: RelaySchemaExecutor): Promise<void> {
  await executor.query(`CREATE TABLE oaath_operation_lane_v1 (
    grant_id text NOT NULL, chain_id bigint NOT NULL, kind text NOT NULL,
    record jsonb,
    PRIMARY KEY (grant_id, chain_id, kind)
  )`);
  await executor.query(`CREATE TABLE oaath_operation_archive_v1 (
    grant_id text NOT NULL, chain_id bigint NOT NULL, kind text NOT NULL,
    user_operation_hash text NOT NULL, record jsonb NOT NULL,
    PRIMARY KEY (grant_id, chain_id, kind, user_operation_hash),
    FOREIGN KEY (grant_id, chain_id, kind) REFERENCES oaath_operation_lane_v1
  )`);
}
const lane = "grant_id = $1 AND chain_id = $2 AND kind = $3";
function keyParts(key: Readonly<OperationStoreKey>) {
  return [key.grantId, key.chainId, key.kind];
}

/**
 * The deployment owns the pool. SDK OperationStore captures records and validates
 * lifecycle transitions; this adapter owns atomic revision/absence guards and
 * archive publication. A permanent lane row also locks initially absent state.
 * A conclusive loss returns false. An uncertain COMMIT throws and is never
 * retried. Rollback/connection release are local cleanup; close borrows no pool.
 */
export function createPostgresOperationStoreAdapter({
  pool,
}: {
  readonly pool: Pool;
}): OperationStoreAdapter {
  async function read(sql: string, args: readonly unknown[]): Promise<unknown> {
    try {
      return (await pool.query(sql, [...args])).rows[0]?.record ?? undefined;
    } catch {
      return relayFailure("relay_store_unavailable", "operation read unavailable");
    }
  }
  return Object.freeze({
    get: (key: Readonly<OperationStoreKey>) =>
      read(`SELECT record FROM oaath_operation_lane_v1 WHERE ${lane}`, keyParts(key)),
    getArchived: (input: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
      read(
        `SELECT record FROM oaath_operation_archive_v1 WHERE ${lane} AND user_operation_hash = $4`,
        [...keyParts(input.key), input.userOperationHash],
      ),
    async compareAndSwap(
      input: Parameters<OperationStoreAdapter["compareAndSwap"]>[0],
    ): Promise<boolean> {
      const client = await pool
        .connect()
        .catch(() => relayFailure("relay_store_unavailable", "operation connection unavailable"));
      let committing = false;
      let discard = false;
      try {
        await client.query("BEGIN");
        const parts = keyParts(input.key);
        await client.query(
          `INSERT INTO oaath_operation_lane_v1 (grant_id, chain_id, kind) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
          parts,
        );
        const row = (
          await client.query(
            `SELECT record, record = $4::jsonb AS matches_archive FROM oaath_operation_lane_v1 WHERE ${lane} FOR UPDATE`,
            [...parts, input.archive === null ? null : JSON.stringify(input.archive.record)],
          )
        ).rows[0];
        let accepted = (row?.record?.storeRevision ?? null) === input.expectedStoreRevision;
        if (
          (
            await client.query(
              `SELECT 1 FROM oaath_operation_archive_v1 WHERE ${lane} AND user_operation_hash = $4`,
              [...parts, input.expectedArchiveAbsentUserOperationHash],
            )
          ).rowCount !== 0
        )
          accepted = false;
        if (input.archive !== null) {
          if (
            row?.matches_archive !== true ||
            input.archive.userOperationHash === input.expectedArchiveAbsentUserOperationHash
          )
            accepted = false;
          if (accepted)
            accepted =
              (
                await client.query(
                  `INSERT INTO oaath_operation_archive_v1 (grant_id, chain_id, kind, user_operation_hash, record) VALUES ($1, $2, $3, $4, $5::jsonb) ON CONFLICT DO NOTHING`,
                  [...parts, input.archive.userOperationHash, JSON.stringify(input.archive.record)],
                )
              ).rowCount === 1;
        }
        if (!accepted) {
          await client.query("ROLLBACK");
          return false;
        }
        await client.query(`UPDATE oaath_operation_lane_v1 SET record = $4::jsonb WHERE ${lane}`, [
          ...parts,
          JSON.stringify(input.next),
        ]);
        committing = true;
        if ((await client.query("COMMIT")).command !== "COMMIT") throw new Error("unproven commit");
        return true;
      } catch {
        if (committing) {
          discard = true;
          return relayFailure("relay_state_ambiguous", "operation commit outcome is unproven");
        }
        try {
          await client.query("ROLLBACK");
        } catch {
          discard = true;
        }
        return relayFailure("relay_store_unavailable", "operation transition unavailable");
      } finally {
        client.release(discard);
      }
    },
    async close() {
      /* Deployment owns the shared pool. */
    },
  });
}
