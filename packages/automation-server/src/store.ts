/**
 * The OAAth SDK's durable ports over PostgreSQL: Grant records, the Operation
 * journal, and client contexts. Records are stored as the exact JSON text the
 * SDK wrote, so compare-and-swap compares what the SDK last read.
 *
 * The Operation journal is also where a run's operation becomes durable. The
 * SDK journals every new UserOperation identity in state `prepared` before it
 * signs or submits it; in that same transaction this adapter copies the hash
 * and nonce onto the plan's one `prepared` run on that lane (the journal key's
 * lane equals the run's stored lane). A new identity no prepared run on its
 * lane claims is refused, so nothing can be sent that a run does not record,
 * and no run can take another lane's operation.
 *
 * ```text
 * state and owner      lane record: the SDK; run.op_hash: this adapter, once
 * persisted evidence   op hash + nonce on the run before any signature or send
 * retry safe?          op_hash set => observe only; op_hash null => never journaled,
 *                      so never signed or sent
 * forbidden            a second identity for a run that already has one, unless
 *                      the earlier one is a never-attempted prepared record
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */
import type {
  GrantStoreAdapter,
  OperationStoreAdapter,
  OperationStoreKey,
  OperationStoreScope,
  StoreRecord,
} from "@oaath/sdk/advanced";
import type { OaathClientContext, OaathContextStore } from "@oaath/sdk/persistence";
import { type Client, type Pool, transaction } from "./db.js";

function parse(text: string | undefined): unknown {
  return text === undefined ? undefined : JSON.parse(text);
}

export function createGrantStore(pool: Pool): GrantStoreAdapter {
  return Object.freeze({
    async get(grantId: string) {
      const result = await pool.query("SELECT record FROM automation_grants WHERE grant_id=$1", [
        grantId,
      ]);
      return parse(result.rows[0]?.record);
    },
    async compareAndSwap(input: {
      grantId: string;
      expectedStoreRevision: number | null;
      next: Readonly<StoreRecord<unknown>>;
    }) {
      const record = JSON.stringify(input.next);
      const result =
        input.expectedStoreRevision === null
          ? await pool.query(
              "INSERT INTO automation_grants(grant_id,store_revision,record) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
              [input.grantId, input.next.storeRevision, record],
            )
          : await pool.query(
              "UPDATE automation_grants SET store_revision=$2,record=$3 WHERE grant_id=$1 AND store_revision=$4",
              [input.grantId, input.next.storeRevision, record, input.expectedStoreRevision],
            );
      return result.rowCount === 1;
    },
    async close() {},
  });
}

function laneOf(key: Readonly<OperationStoreKey>): number {
  return key.lane ?? 0;
}

interface JournaledOperation {
  readonly state: string;
  readonly identity: { readonly userOperationHash: string; readonly nonce: string };
}

/** Binds a newly journaled execution identity to the plan's prepared run, or refuses it. */
async function claimIdentity(
  client: Client,
  key: Readonly<OperationStoreKey>,
  current: JournaledOperation | undefined,
  next: JournaledOperation,
): Promise<boolean> {
  if (key.kind !== "execution" || next.state !== "prepared") return true;
  if (current?.identity.userOperationHash === next.identity.userOperationHash) return true;
  // A never-attempted prepared identity may be replaced by the SDK; nothing else may.
  const replaceable = current?.state === "prepared" ? current.identity.userOperationHash : null;
  const claimed = await client.query(
    `UPDATE automation_runs r SET op_hash=$2, op_nonce=$3
     FROM automation_plans p
     WHERE p.id=r.plan_id AND p.grant_id=$1 AND r.lane=$5 AND r.status='prepared'
       AND (r.op_hash IS NULL OR r.op_hash=$4)`,
    [key.grantId, next.identity.userOperationHash, next.identity.nonce, replaceable, laneOf(key)],
  );
  return claimed.rowCount === 1;
}

export function createOperationStore(pool: Pool): OperationStoreAdapter {
  return Object.freeze({
    async get(key: Readonly<OperationStoreKey>) {
      const result = await pool.query(
        "SELECT record FROM automation_operations WHERE grant_id=$1 AND chain_id=$2 AND kind=$3 AND lane=$4",
        [key.grantId, key.chainId, key.kind, laneOf(key)],
      );
      return parse(result.rows[0]?.record);
    },
    async list(scope: Readonly<OperationStoreScope>) {
      const result = await pool.query(
        "SELECT record FROM automation_operations WHERE grant_id=$1 AND chain_id=$2 AND kind=$3 ORDER BY lane",
        [scope.grantId, scope.chainId, scope.kind],
      );
      return result.rows.map((row) => parse(row.record));
    },
    async getArchived(input: {
      key: Readonly<OperationStoreKey>;
      userOperationHash: `0x${string}`;
    }) {
      const { key } = input;
      const result = await pool.query(
        "SELECT record FROM automation_operation_archive WHERE grant_id=$1 AND chain_id=$2 AND kind=$3 AND lane=$4 AND user_operation_hash=$5",
        [key.grantId, key.chainId, key.kind, laneOf(key), input.userOperationHash],
      );
      return parse(result.rows[0]?.record);
    },
    async compareAndSwap(input: {
      key: Readonly<OperationStoreKey>;
      expectedStoreRevision: number | null;
      next: Readonly<StoreRecord<unknown>>;
      expectedArchiveAbsentUserOperationHash: `0x${string}`;
      archive: Readonly<{
        userOperationHash: `0x${string}`;
        record: Readonly<StoreRecord<unknown>>;
      }> | null;
    }) {
      const { key } = input;
      const lane = laneOf(key);
      const scope = [key.grantId, key.chainId, key.kind, lane];
      // A refused write rolls back, so a half-claimed identity never persists.
      const refuse = new Error("operation_store_refused");
      try {
        return await transaction(pool, async (client) => {
          const row = (
            await client.query(
              "SELECT store_revision, record FROM automation_operations WHERE grant_id=$1 AND chain_id=$2 AND kind=$3 AND lane=$4 FOR UPDATE",
              scope,
            )
          ).rows[0] as { store_revision: number; record: string } | undefined;
          if (
            input.expectedStoreRevision === null
              ? row !== undefined
              : row?.store_revision !== input.expectedStoreRevision
          )
            return false;
          const absent = await client.query(
            "SELECT 1 FROM automation_operation_archive WHERE grant_id=$1 AND chain_id=$2 AND kind=$3 AND lane=$4 AND user_operation_hash=$5",
            [...scope, input.expectedArchiveAbsentUserOperationHash],
          );
          if (absent.rowCount !== 0) return false;
          if (input.archive !== null) {
            if (
              row === undefined ||
              input.archive.userOperationHash === input.expectedArchiveAbsentUserOperationHash ||
              row.record !== JSON.stringify(input.archive.record)
            )
              return false;
            const archived = await client.query(
              "INSERT INTO automation_operation_archive(grant_id,chain_id,kind,lane,user_operation_hash,record) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
              [...scope, input.archive.userOperationHash, row.record],
            );
            if (archived.rowCount !== 1) return false;
          }
          const current =
            row === undefined ? undefined : (JSON.parse(row.record).value as JournaledOperation);
          if (!(await claimIdentity(client, key, current, input.next.value as JournaledOperation)))
            throw refuse;
          await client.query(
            `INSERT INTO automation_operations(grant_id,chain_id,kind,lane,store_revision,record)
             VALUES($1,$2,$3,$4,$5,$6)
             ON CONFLICT (grant_id,chain_id,kind,lane) DO UPDATE SET store_revision=EXCLUDED.store_revision, record=EXCLUDED.record`,
            [...scope, input.next.storeRevision, JSON.stringify(input.next)],
          );
          return true;
        });
      } catch (error) {
        if (error === refuse) return false;
        throw error;
      }
    },
    async close() {},
  });
}

export function createContextStore(pool: Pool): OaathContextStore {
  return Object.freeze({
    async read(bindingId: string) {
      const result = await pool.query(
        "SELECT record FROM automation_contexts WHERE binding_id=$1",
        [bindingId],
      );
      return parse(result.rows[0]?.record);
    },
    async write(context: Readonly<OaathClientContext>) {
      await pool.query(
        "INSERT INTO automation_contexts(binding_id,record) VALUES($1,$2) ON CONFLICT (binding_id) DO UPDATE SET record=EXCLUDED.record",
        [context.bindingId, JSON.stringify(context)],
      );
    },
    async clear(bindingId: string) {
      await pool.query("DELETE FROM automation_contexts WHERE binding_id=$1", [bindingId]);
    },
    async close() {},
  });
}

/**
 * Stores for wallet-provider paths this service never takes (EIP-5792 bundles,
 * prepared external calls, local key handles, cleanup checkpoints). They hold
 * nothing durable because nothing durable is ever written to them.
 */
export function createUnusedStores() {
  const records = () => {
    const map = new Map<string, Readonly<StoreRecord<unknown>>>();
    return Object.freeze({
      async get(key: unknown) {
        return map.get(JSON.stringify(key));
      },
      async compareAndSwap(input: {
        key: unknown;
        expectedStoreRevision: number | null;
        next: Readonly<StoreRecord<unknown>>;
      }) {
        const id = JSON.stringify(input.key);
        const current = map.get(id);
        if (
          input.expectedStoreRevision === null
            ? current !== undefined
            : current?.storeRevision !== input.expectedStoreRevision
        )
          return false;
        map.set(id, input.next);
        return true;
      },
      async close() {},
    });
  };
  const checkpoints = new Map<string, unknown>();
  return Object.freeze({
    walletCallBundles: records(),
    preparedCallContexts: records(),
    keys: Object.freeze({
      async store() {},
      async get() {
        return undefined;
      },
      async delete() {},
      async close() {},
    }),
    cleanup: Object.freeze({
      async read(cleanupId: string) {
        return checkpoints.get(cleanupId);
      },
      async write(checkpoint: Readonly<{ cleanupId: string }>) {
        checkpoints.set(checkpoint.cleanupId, checkpoint);
      },
      async clear(cleanupId: string) {
        checkpoints.delete(cleanupId);
      },
      async close() {},
    }),
  });
}
