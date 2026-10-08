/**
 * One process: the HTTP API, the scheduler and the executors over one
 * PostgreSQL database. Any number of replicas may share the database.
 *
 * @author taek <leekt216@gmail.com>
 */
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createBudgetedChains } from "./chain.js";
import type { AutomationServiceConfig } from "./config.js";
import type { ServiceContext } from "./context.js";
import { createPool, initializeSchema, now } from "./db.js";
import { executorLoop, grantGateway, type OpenGateway } from "./executor.js";
import { createHttpServer } from "./http.js";
import { tick } from "./scheduler.js";

export interface AutomationService {
  readonly context: ServiceContext;
  /** The bound HTTP address, e.g. `http://127.0.0.1:4317`. */
  readonly url: string;
  readonly close: () => Promise<void>;
}

export interface StartOptions {
  /** Executor loops in this process. */
  readonly executors?: number;
  /** Replaces the Grant-backed gateway; for deterministic tests only. */
  readonly gateway?: OpenGateway;
  readonly clock?: () => number;
}

export async function startAutomationService(
  config: AutomationServiceConfig,
  options: StartOptions = {},
): Promise<AutomationService> {
  const pool = createPool(config.databaseUrl);
  await initializeSchema(pool);
  const clock = options.clock ?? (() => Date.now());
  const chains = createBudgetedChains(config, clock);
  const context: ServiceContext = Object.freeze({
    config,
    pool,
    definitions: new Map(config.definitions.map((definition) => [definition.id, definition])),
    chain: chains.chain,
    budgetRetryAt: chains.retryAt,
    now: options.clock === undefined ? now : () => Math.floor(clock() / 1000),
    replicaId: randomBytes(8).toString("hex"),
  });
  const controller = new AbortController();
  const gateway = options.gateway ?? grantGateway(context);
  const loops = [
    ...Array.from({ length: options.executors ?? 4 }, () =>
      executorLoop(context, gateway, controller.signal),
    ),
    (async () => {
      while (!controller.signal.aborted) {
        await tick(context).catch(() =>
          console.error(JSON.stringify({ event: "scheduler_deferred" })),
        );
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    })(),
  ];
  const server = createHttpServer(context);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.listen.port, config.listen.host, resolve);
  });
  const address = server.address() as AddressInfo;
  return Object.freeze({
    context,
    url: `http://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`,
    async close() {
      controller.abort();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await Promise.all(loops);
      await pool.end();
    },
  });
}
