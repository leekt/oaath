/**
 * @oaath/server/postgres — the explicit Node/PostgreSQL subpath.
 *
 * Kept out of the package's main entry so no browser or edge graph can pull the
 * driver in by accident.
 *
 * @author taek <leekt216@gmail.com>
 */

export type { RelaySchemaExecutor } from "./store/postgres/schema.js";
export {
  createPostgresRelaySchema,
  OAATH_RELAY_POSTGRES_SCHEMA_STATEMENTS,
  OAATH_RELAY_POSTGRES_SCHEMA_VERSION,
} from "./store/postgres/schema.js";
export type { PostgresRelayStoreOptions } from "./store/postgres/store.js";
export { createPostgresRelayStore } from "./store/postgres/store.js";
