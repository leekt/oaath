import { createOAAth, type Oaath } from "@oaath/sdk";
import type { OaathChainCapability } from "@oaath/sdk/advanced";
import { createKernelV4Reads, ecdsaKey } from "@oaath/sdk/kernel";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import { IDBFactory } from "fake-indexeddb";
import { createPublicClient, http } from "viem";
import { LOCAL_ISSUER, LOCAL_REDIRECT, localClientBinding } from "./anvil-binding.js";
import { createLocalAnvilObservation } from "./anvil-observation.mjs";
import { openLocalClientStores } from "./anvil-stores.js";

/** Public test-environment metadata, never credentials or a copy of SDK records. */
export interface LocalAnvilRecovery {
  readonly version: "oaath.local-anvil-recovery/v2";
  readonly existingAccount: `0x${string}` | null;
  readonly owner: `0x${string}`;
  readonly session: `0x${string}`;
  readonly chains: readonly Readonly<{
    chainId: number;
    rpcUrl: string;
    validator: `0x${string}`;
    feePayer: Readonly<{ address: `0x${string}`; balance: string }>;
  }>[];
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) throw new Error();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(String(key))))
    throw new Error();
  return Object.fromEntries(keys.map((key) => [key, Reflect.get(value, key)]));
}

function address(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) throw new Error();
  return value.toLowerCase() as `0x${string}`;
}

/** Capture once before any disk or network access; only loopback RPCs are accepted. */
export function captureLocalAnvilRecovery(value: unknown): Readonly<LocalAnvilRecovery> {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Reflect.get(value, "version") !== "oaath.local-anvil-recovery/v2"
    )
      throw new Error();
    const input = record(value, ["version", "owner", "session", "chains", "existingAccount"]);
    if (!Array.isArray(input.chains) || input.chains.length < 1 || input.chains.length > 2)
      throw new Error();
    const chains = input.chains.map((value) => {
      const chain = record(value, ["chainId", "rpcUrl", "validator", "feePayer"]);
      if (
        typeof chain.chainId !== "number" ||
        !Number.isSafeInteger(chain.chainId) ||
        chain.chainId < 1
      )
        throw new Error();
      if (
        typeof chain.rpcUrl !== "string" ||
        !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(chain.rpcUrl)
      )
        throw new Error();
      const url = new URL(chain.rpcUrl);
      if (Number(url.port) > 65535) throw new Error();
      const feePayer = record(chain.feePayer, ["address", "balance"]);
      if (typeof feePayer.balance !== "string" || !/^(0|[1-9][0-9]{0,77})$/u.test(feePayer.balance))
        throw new Error();
      return Object.freeze({
        chainId: chain.chainId,
        rpcUrl: chain.rpcUrl,
        validator: address(chain.validator),
        feePayer: Object.freeze({ address: address(feePayer.address), balance: feePayer.balance }),
      });
    });
    if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length) throw new Error();
    return Object.freeze({
      version: "oaath.local-anvil-recovery/v2",
      existingAccount: input.existingAccount === null ? null : address(input.existingAccount),
      owner: address(input.owner),
      session: address(input.session),
      chains: Object.freeze(chains),
    });
  } catch {
    throw new Error("local_fixture_recovery_invalid");
  }
}

async function unavailable(): Promise<never> {
  throw new Error("local_fixture_recovery_read_only");
}

/**
 * Reopens direct Grant/Operation/context state after process loss. The existing
 * Anvil processes must remain alive. No credentials are retained or restored;
 * signing, permission requests, quotes and submission are unavailable.
 */
export async function openLocalAnvilRecoveryClient(
  input: Readonly<{
    recovery: unknown;
    stateDirectory: string;
  }>,
): Promise<Readonly<Oaath>> {
  const recovery = captureLocalAnvilRecovery(input.recovery);
  const stateDirectory = input.stateDirectory;
  if (typeof stateDirectory !== "string" || stateDirectory.length === 0)
    throw new Error("local_fixture_storage_invalid");
  const storage = await openLocalClientStores(new IDBFactory(), stateDirectory);
  try {
    const chains: OaathChainCapability[] = recovery.chains.map((chain) => {
      const reader = createPublicClient({
        transport: http(chain.rpcUrl, { retryCount: 0, timeout: 5000 }),
      });
      const reads = createKernelV4Reads(reader);
      return {
        chainId: chain.chainId,
        reads: {
          async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
            switch (request.type) {
              case "chain_id":
              case "code":
              case "runtime_code_hash":
              case "kernel_factory_implementation":
              case "kernel_factory_account":
                return reads.read(request);
              case "kernel_account_implementation":
                return reads.read({
                  type: request.type,
                  chainId: request.chainId,
                  account: request.account,
                });
              default:
                return unavailable();
            }
          },
        },
        observation: createLocalAnvilObservation({
          chainId: chain.chainId,
          async rpc(method: string, params: unknown[]) {
            try {
              const response = await fetch(chain.rpcUrl, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
                signal: AbortSignal.timeout(5000),
              });
              const body = await response.json();
              if (!response.ok || body.error || !("result" in body)) throw new Error();
              return body.result;
            } catch {
              throw new Error("local_fixture_observation_unavailable");
            }
          },
        }),
        bundler: { probe: unavailable },
        submission: { open: unavailable },
        quote: unavailable,
        usage: unavailable,
        feePayer: chain.feePayer,
        paymasterService: null,
        staticPaymasterConfigurationHash: null,
      };
    });
    // Resume still uses authenticated relay protocol. A new local relay has no
    // prior request, which the SDK explicitly allows after durable validation.
    const token = crypto.randomUUID();
    const relay = createRelayHandler({
      store: createMemoryRelayStore(),
      ownerRouting: { resolveOwner: unavailable },
      authentication: {
        async authenticate(request) {
          return request.headers.get("authorization") === `Bearer ${token}`
            ? {
                role: "client",
                clientId: "fixture-client",
                subject: "fixture-subject",
                redirectUris: [LOCAL_REDIRECT],
                organizationAudience: null,
              }
            : null;
        },
      },
      kms: { encrypt: unavailable, decrypt: unavailable },
      clock: { now: () => Date.now() },
    });
    const validator = recovery.chains[0]?.validator;
    if (!validator) throw new Error("local_fixture_recovery_invalid");
    const client = createOAAth({
      binding: localClientBinding(recovery.owner, recovery.session, recovery.existingAccount),
      issuer: {
        url: LOCAL_ISSUER,
        async fetch(request: Request) {
          if (
            request.method !== "POST" ||
            new URL(request.url).pathname !== "/authorization/resume"
          )
            return unavailable();
          const headers = new Headers(request.headers);
          headers.set("authorization", `Bearer ${token}`);
          return relay(new Request(request, { headers }));
        },
        async signOut() {},
      },
      authorization: { authorize: unavailable },
      invalidation: { invalidateCapability: unavailable },
      stores: storage.stores,
      chains,
      signing: {
        owner: ecdsaKey({ account: { address: recovery.owner, sign: unavailable }, validator }),
        session: ecdsaKey({ account: { address: recovery.session, sign: unavailable }, validator }),
      },
      localKeyIds: [],
      now: () => Math.floor(Date.now() / 1000),
    });
    return Object.freeze({
      ...client,
      async close() {
        const results = await Promise.allSettled([client.close()]);
        results.push(...(await Promise.allSettled([storage.close()])));
        if (results.some((result) => result.status === "rejected"))
          throw new Error("local_fixture_cleanup_failed");
      },
    });
  } catch {
    await storage.close().catch(() => undefined);
    throw new Error("local_fixture_recovery_unavailable");
  }
}
