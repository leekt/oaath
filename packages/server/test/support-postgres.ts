/**
 * Disposable PostgreSQL harness. Every run owns a fresh schema, and every
 * harness owns an independent pool, so a "restart" recreates every in-memory
 * instance instead of reusing a warm connection.
 *
 * Gated by `OAATH_REQUIRE_POSTGRES=1`; the default gate never contacts a
 * database. `OAATH_POSTGRES_URL` selects the local server.
 *
 * @author taek <leekt216@gmail.com>
 */

import pg from "pg";
import { createRelayHandler } from "../src/relay/handler.js";
import { createPostgresRelaySchema } from "../src/store/postgres/schema.js";
import { createPostgresRelayStore } from "../src/store/postgres/store.js";
import {
  createTestAuthentication,
  createTestClock,
  createTestKms,
  type Harness,
  type TestClock,
} from "./support.js";

export const requirePostgres = process.env.OAATH_REQUIRE_POSTGRES === "1";

const connectionString = process.env.OAATH_POSTGRES_URL ?? "postgres://localhost:5432/postgres";

export interface PostgresFixture {
  readonly schema: string;
  /** A fresh independent pool bound to the disposable schema. */
  createPool(): pg.Pool;
  end(): Promise<void>;
}

export async function createPostgresFixture(): Promise<PostgresFixture> {
  const admin = new pg.Pool({ connectionString, max: 2 });
  const schema = `oaath_relay_test_${crypto.randomUUID().replaceAll("-", "")}`;
  const pools: pg.Pool[] = [];

  const createPool = (): pg.Pool => {
    const pool = new pg.Pool({ connectionString, max: 4, options: `-c search_path=${schema}` });
    pools.push(pool);
    return pool;
  };

  await admin.query(`CREATE SCHEMA "${schema}"`);
  const setup = createPool();
  await createPostgresRelaySchema(setup);
  await setup.end();

  return {
    schema,
    createPool,
    async end() {
      for (const pool of pools) {
        try {
          await pool.end();
        } catch {
          // A test may already have ended its own pool.
        }
      }
      await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
      await admin.end();
    },
  };
}

export interface PostgresHarness extends Harness {
  /** Ends this harness's pool: the process-restart boundary. */
  shutdown(): Promise<void>;
}

export function createPostgresHarness(
  fixture: PostgresFixture,
  clock: TestClock = createTestClock(),
): PostgresHarness {
  const pool = fixture.createPool();
  const store = createPostgresRelayStore({ pool });
  const kms = createTestKms();
  return {
    handler: createRelayHandler({
      store,
      authentication: createTestAuthentication(),
      kms,
      clock,
    }),
    store,
    clock,
    kms,
    shutdown: async () => {
      await store.close();
      await pool.end();
    },
  };
}
