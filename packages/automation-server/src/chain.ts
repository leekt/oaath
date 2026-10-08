/**
 * Budgeted chain ports. Every request to a chain RPC, bundler or paymaster
 * passes one shared per-role budget before it leaves the process; the ports
 * are rebuilt each budget window so their own lifetime cap never outlives it.
 * No retries beyond the ports' single bounded retry, and no fallback route.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CetaneChainCapability, createCetaneChainPorts } from "@oaath/sdk/cetane";
import { RequestBudget } from "./budget.js";
import type { AutomationServiceConfig } from "./config.js";

export interface BudgetedChains {
  readonly chain: (chainId: number) => Readonly<CetaneChainCapability>;
  readonly retryAt: () => number | null;
  readonly snapshot: () => readonly ReturnType<RequestBudget["snapshot"]>[];
}

export function createBudgetedChains(
  config: AutomationServiceConfig,
  clock: () => number = Date.now,
  fetcher: typeof fetch = fetch,
): BudgetedChains {
  const windowMs = config.budgets.windowSeconds * 1000;
  const budgets = {
    rpc: new RequestBudget("rpc", config.budgets.rpc, windowMs, clock),
    bundler: new RequestBudget("bundler", config.budgets.bundler, windowMs, clock),
    paymaster: new RequestBudget("paymaster", config.budgets.paymaster, windowMs, clock),
  };
  const roles = new Map<string, RequestBudget>();
  for (const endpoints of config.chains.values()) {
    roles.set(endpoints.rpcUrl, budgets.rpc);
    roles.set(endpoints.bundlerUrl, budgets.bundler);
    if (endpoints.paymasterUrl !== null) roles.set(endpoints.paymasterUrl, budgets.paymaster);
  }
  let ports: ReadonlyMap<number, Readonly<CetaneChainCapability>> | null = null;
  let portsWindow = -1;
  let exhaustedUntil: number | null = null;

  function build() {
    const created = createCetaneChainPorts(
      Object.fromEntries(
        [...config.chains].map(([chainId, endpoints]) => [
          chainId,
          {
            publicRpcUrls: [endpoints.rpcUrl],
            bundlerUrl: endpoints.bundlerUrl,
            ...(endpoints.paymasterUrl === null ? {} : { paymasterUrl: endpoints.paymasterUrl }),
            ...(endpoints.relayPaysGas ? { relayPaysGas: true } : {}),
          },
        ]),
      ),
      {
        maxRequests: config.budgets.rpc + config.budgets.bundler + config.budgets.paymaster,
        maxConcurrency: 8,
        retry: { attempts: 1 },
        timeoutMs: 10_000,
        fetch: async (request: Request) => {
          const url = request.url.replace(/\/$/u, "");
          const budget = roles.get(url) ?? roles.get(request.url);
          // An endpoint this configuration does not name is never contacted.
          if (budget === undefined) throw new TypeError("endpoint_unconfigured");
          try {
            budget.take();
          } catch (error) {
            exhaustedUntil = Math.ceil(budget.retryAt / 1000);
            throw error;
          }
          return fetcher(request);
        },
      },
    );
    return new Map(created.map((port) => [port.chainId, port]));
  }

  return Object.freeze({
    chain(chainId: number) {
      const window = Math.floor(clock() / windowMs);
      if (ports === null || portsWindow !== window) {
        ports = build();
        portsWindow = window;
      }
      const port = ports.get(chainId);
      if (port === undefined) throw new TypeError("chain_unconfigured");
      return port;
    },
    retryAt() {
      if (exhaustedUntil !== null && exhaustedUntil * 1000 <= clock()) exhaustedUntil = null;
      return exhaustedUntil;
    },
    snapshot: () => Object.values(budgets).map((budget) => budget.snapshot()),
  });
}
