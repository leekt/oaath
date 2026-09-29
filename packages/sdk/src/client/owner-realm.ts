/** Owner-only existing-account execution. The Operation journal remains the lifecycle owner. */
import { captureDenseArray, captureRecord } from "@oaath/protocol";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { type KernelV33Reads, kernelV33Deployment } from "../kernel/deployment/v33.js";
import { type EcdsaWalletClient, ecdsaWalletKey } from "../kernel/key/ecdsa.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { createOperationObserver, type OperationObserver } from "../operation-observer.js";
import {
  createOperationRunner,
  type OperationPreparationCapability,
  type OperationStartResult,
  type OperationSubmissionCapability,
} from "../operation-runner.js";
import { type OaathDatabase, openOaathDatabase } from "../persistence/indexeddb/database.js";
import { createIndexedDbOperationStoreAdapter } from "../persistence/indexeddb/operation-store.js";
import { probeBundlerCapability } from "../routing/bundler.js";
import { routingAddress } from "../routing/capabilities.js";
import { decideExecution } from "../routing/decide.js";
import { prepareSponsoredKernelOperation } from "../routing/sponsorship.js";
import type { OaathExecutionDecision } from "../routing/types.js";
import { OperationStore, type OperationStoreAdapter, type OperationStoreKey } from "../store.js";
import {
  captureConnectedEoa,
  connectedEoaReview,
  type OaathConnectedEoaFallbackReview,
  withConnectedEoaFallback,
} from "./connected-eoa.js";
import { clientFail, clientFailure, exactClientRecord, mapClientFailure } from "./errors.js";
import {
  captureCalls,
  captureChainCapability,
  captureSubmissionSession,
  type OaathCallInput,
  type OaathChainCapability,
  quoteFields,
} from "./grant-handle.js";
import {
  createOperationHandle,
  type OaathOperationHandle,
  operationOutcome,
} from "./operation-handle.js";
import { capturePaymasterService, capturePlainCalls } from "./sponsorship.js";

interface OwnerChain extends OaathChainCapability {
  readonly reads: OaathChainCapability["reads"] & KernelV33Reads;
}
export interface OaathOwnerConfiguration {
  readonly mode: "owner";
  readonly chains: readonly Readonly<OwnerChain>[];
  /** Defaults to the shared browser IndexedDB operation store; this realm owns close. */
  readonly operations?: OperationStoreAdapter;
}
export interface OaathOwnerCallsReview {
  /** The full call list was estimated as one operation without signing or reserving its lane. */
  readonly capacity: Readonly<{
    kind: "single-operation";
    gas: Readonly<{
      callGasLimit: string;
      verificationGasLimit: string;
      preVerificationGas: string;
    }>;
  }>;
  readonly fallback: Readonly<OaathConnectedEoaFallbackReview> | null;
  readonly paymasterService: Readonly<{ url: string }> | null;
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly kernelVersion: "0.3.3";
  readonly calls: readonly Readonly<OaathCallInput>[];
  readonly signer: "owner";
  readonly route: "bundler";
  readonly reasons: OaathExecutionDecision["reasons"];
}
export interface OaathOwnerHandle {
  readonly reviewCalls: (input: unknown) => Promise<Readonly<OaathOwnerCallsReview>>;
  readonly sendCalls: (input: unknown) => Promise<Readonly<OaathOperationHandle>>;
}
export interface OaathOwnerAccount {
  readonly address: `0x${string}`;
  readonly owner: (wallet: EcdsaWalletClient) => Readonly<OaathOwnerHandle>;
  /** Exact saved-operation recovery requires no connected wallet. */
  readonly getOperation: (input: unknown) => Promise<Readonly<OaathOperationHandle> | null>;
}
export interface OaathOwnerClient {
  /** Existing ECDSA-root Kernel v3.3 only; binding checks the version on each send. */
  readonly account: (address: `0x${string}`) => Readonly<OaathOwnerAccount>;
  readonly close: () => Promise<void>;
}

const TIMEOUT = 10_000;
const ZERO_GAS = Object.freeze({
  callGasLimit: "0",
  verificationGasLimit: "0",
  preVerificationGas: "0",
  maxFeePerGas: "0",
  maxPriorityFeePerGas: "0",
});
const nothing = async () => undefined;
const forbidden = async (): Promise<never> =>
  clientFail("oaath_client_internal", "observation cannot prepare or submit");

export function createOwnerRealm(value: unknown): Readonly<OaathOwnerClient> {
  const fail = clientFailure("oaath_client_input_invalid");
  const captured = captureRecord(value, "owner configuration", new WeakSet(), fail);
  const config = exactClientRecord(
    captured,
    ["mode", "chains", ...(Object.hasOwn(captured, "operations") ? ["operations"] : [])],
    "owner configuration",
    new WeakSet(),
  );
  if (config.mode !== "owner") return fail("owner mode is required");
  const entries = captureDenseArray(config.chains, "owner chains", new WeakSet(), fail);
  if (entries.length < 1 || entries.length > 32)
    return fail("owner chains must hold 1 to 32 entries");
  const chains = new Map<number, Readonly<OwnerChain>>();
  for (const entry of entries) {
    const chain = captureChainCapability(entry) as Readonly<OwnerChain>;
    if (chains.has(chain.chainId)) return fail("owner chains repeat a chain");
    chains.set(chain.chainId, chain);
  }
  let adapter: OperationStoreAdapter | undefined;
  if (Object.hasOwn(config, "operations")) {
    const fields = exactClientRecord(
      config.operations,
      ["get", "getArchived", "compareAndSwap", "close"],
      "owner operation store",
      new WeakSet(),
    );
    if (Object.values(fields).some((field) => typeof field !== "function"))
      return fail("owner operation store is invalid");
    adapter = fields as unknown as OperationStoreAdapter;
  }
  let database: OaathDatabase | undefined;
  let opening: Promise<OperationStoreAdapter> | undefined;
  let closed = false;
  let closing: Promise<void> | null = null;
  let adapterClosed = false;
  const active = new Set<Promise<unknown>>();
  const handles = new Set<Readonly<OaathOperationHandle>>();
  const observers = new Map<number, Readonly<OperationObserver>>();
  function assertOpen() {
    if (closed) clientFail("oaath_client_closed", "owner client is closed");
  }
  async function activity<T>(work: () => Promise<T>): Promise<T> {
    assertOpen();
    const pending = Promise.resolve()
      .then(work)
      .catch((error) => mapClientFailure(error, "owner operation failed"))
      .finally(() => active.delete(pending));
    active.add(pending);
    return pending;
  }
  async function storage(): Promise<OperationStoreAdapter> {
    if (adapter) return adapter;
    opening ??= openOaathDatabase().then((opened) => {
      database = opened;
      adapter = createIndexedDbOperationStoreAdapter(opened);
      return adapter;
    });
    return opening;
  }
  async function store(): Promise<OperationStore> {
    const port = await storage();
    return new OperationStore({
      get: (key) => port.get(key),
      getArchived: (key) => port.getArchived(key),
      compareAndSwap: (input) => port.compareAndSwap(input),
      close: nothing,
    } satisfies OperationStoreAdapter);
  }
  function chainFor(id: unknown): Readonly<OwnerChain> {
    if (typeof id !== "number" || !Number.isSafeInteger(id) || id < 1)
      return fail("owner chain is invalid");
    const chain = chains.get(id);
    if (!chain)
      return clientFail(
        "oaath_client_capability_unsupported",
        "owner chain is not configured",
        "chain_not_configured",
      );
    return chain;
  }
  async function runner(
    chain: Readonly<OwnerChain>,
    prepare?: OperationPreparationCapability["prepare"],
    openSubmission?: OperationSubmissionCapability["openSubmission"],
  ) {
    let observer = observers.get(chain.chainId);
    if (!observer) {
      observer = createOperationObserver(chain.observation);
      observers.set(chain.chainId, observer);
    }
    const shared = observer;
    return createOperationRunner({
      terminalBehavior: prepare ? "replace" : "reuse_same_kind",
      requestHash: null,
      store: await store(),
      observer: {
        observeOperation: (input: unknown) => shared.observeOperation(input),
        close: nothing,
      },
      preparation: {
        prepare: prepare ?? forbidden,
        reserveOperation: nothing,
        releaseOperationReservation: nothing,
        authorizeOperation: nothing,
        abandonOperation: nothing,
        confirmOperationPublished: nothing,
        close: nothing,
      },
      submission: { openSubmission: openSubmission ?? forbidden, close: nothing },
    });
  }
  async function handle(
    chain: Readonly<OwnerChain>,
    key: Readonly<OperationStoreKey>,
    initial: OperationStartResult,
  ) {
    operationOutcome(initial);
    let created: Readonly<OaathOperationHandle>;
    created = createOperationHandle({
      runner: await runner(chain),
      key,
      kind: "execution",
      timeoutMs: TIMEOUT,
      now: () => Math.floor(Date.now() / 1000),
      initial,
      observation: chain.observation.read,
      onClosed: () => handles.delete(created),
    });
    handles.add(created);
    return created;
  }
  function account(addressValue: `0x${string}`): Readonly<OaathOwnerAccount> {
    assertOpen();
    const address = routingAddress(addressValue, "owner account", fail);
    // This is an operation lane label only. No Grant or permission is created.
    const contextId = `owner:kernel:0.3.3:${address}`;
    const keyFor = (chainId: number) =>
      Object.freeze({ grantId: contextId, chainId, kind: "execution" as const });
    return Object.freeze({
      address,
      owner(wallet: EcdsaWalletClient): Readonly<OaathOwnerHandle> {
        assertOpen();
        const key = (() => {
          try {
            return ecdsaWalletKey({ wallet, validator: kernelV33Deployment(1).ecdsaValidator });
          } catch (error) {
            return mapClientFailure(error, "owner wallet could not be captured");
          }
        })();
        async function shape(value: unknown) {
          assertOpen();
          const context = new WeakSet<object>();
          const request = capturePlainCalls(value, context);
          const feePayer = Object.hasOwn(request, "feePayer")
            ? captureConnectedEoa(request.feePayer, context)
            : null;
          const chain = chainFor(request.chain);
          const calls = captureCalls(request.calls, context);
          const sponsorship = Object.hasOwn(request, "paymasterService")
            ? capturePaymasterService(request.paymasterService, chain.paymasterService, context)
            : null;
          const runtime = createKernelRuntime({
            deployment: kernelV33Deployment(chain.chainId),
            operator: ownerOperator({ key }),
            reads: chain.reads,
            ...(chain.gas === undefined ? {} : { gas: chain.gas }),
          });
          const bound = await runtime.bindAccount({ address });
          assertOpen();
          const simulation = runtime.prepareOperation({
            kind: "execution",
            grantId: contextId,
            account: bound,
            nonceKey: "0",
            sequence: "0",
            calls,
            gas: ZERO_GAS,
          });
          const bundler = await probeBundlerCapability({
            capability: chain.bundler,
            request: { chainId: chain.chainId, entryPoint: runtime.deployment.entryPoint.address },
            timeoutMs: TIMEOUT,
          });
          const decision = decideExecution({
            operationKind: "execution",
            signer: "owner",
            sessionCoverage: "uncovered",
            bundler,
            feePayer: null,
          });
          if (decision.route !== "bundler")
            return clientFail(
              "oaath_client_route_unavailable",
              "owner bundler route is unavailable",
            );
          return { chain, calls, runtime, bound, simulation, decision, sponsorship, feePayer };
        }
        async function estimate(resolved: Awaited<ReturnType<typeof shape>>) {
          const { chain, calls, runtime, bound, simulation, sponsorship } = resolved;
          assertOpen();
          const quote = quoteFields(
            await chain.quote({
              purpose: sponsorship === null ? "estimate" : "sponsorship",
              chainId: chain.chainId,
              kind: "execution",
              signer: "owner",
              account: address,
              mode: "standard",
              validation: runtime.validation,
              calls,
              paymaster: null,
              simulation: { prepared: simulation, signature: runtime.dummySignature },
            }),
          );
          const operation = {
            kind: "execution" as const,
            grantId: contextId,
            account: bound,
            nonceKey: quote.nonceKey,
            sequence: quote.sequence,
            calls,
            gas: quote.gas,
          };
          return sponsorship === null
            ? runtime.prepareOperation(operation)
            : prepareSponsoredKernelOperation({
                runtime,
                operation,
                simulationSignature: runtime.dummySignature,
                sponsorship,
              });
        }
        return Object.freeze({
          reviewCalls: (value: unknown) =>
            activity(async () => {
              const resolved = await shape(value);
              const estimated = await estimate(resolved);
              assertOpen();
              return Object.freeze({
                capacity: Object.freeze({
                  kind: "single-operation" as const,
                  gas: Object.freeze({
                    callGasLimit: estimated.userOperation.callGasLimit,
                    verificationGasLimit: estimated.userOperation.verificationGasLimit,
                    preVerificationGas: estimated.userOperation.preVerificationGas,
                  }),
                }),
                chainId: resolved.chain.chainId,
                fallback: connectedEoaReview(resolved.feePayer),
                account: address,
                kernelVersion: "0.3.3" as const,
                calls: resolved.calls,
                signer: "owner" as const,
                route: "bundler" as const,
                reasons: resolved.decision.reasons,
                paymasterService:
                  resolved.sponsorship === null
                    ? null
                    : Object.freeze({ url: resolved.chain.paymasterService!.url }),
              });
            }),
          sendCalls: (value: unknown) =>
            activity(async () => {
              const resolved = await shape(value);
              const { chain, runtime, feePayer } = resolved;
              const lane = keyFor(chain.chainId);
              const sender = await runner(
                chain,
                async () => {
                  assertOpen();
                  return estimate(resolved);
                },
                async (prepared) => {
                  assertOpen();
                  const signature = await runtime.signOperation(prepared);
                  assertOpen();
                  const submission = {
                    prepared,
                    signature,
                    route: "bundler" as const,
                    feePayer: null,
                  };
                  return withConnectedEoaFallback(
                    captureSubmissionSession(await chain.submission.open(submission)),
                    submission,
                    feePayer,
                  );
                },
              );
              let result: OperationStartResult;
              try {
                const at = Math.floor(Date.now() / 1000);
                result = await sender.startOperation({
                  kind: "execution",
                  key: lane,
                  preparedAt: at,
                  attemptedAt: at,
                  submittedAt: at,
                  observedAt: at,
                  timeoutMs: TIMEOUT,
                });
              } finally {
                await sender.close().catch(() => undefined);
              }
              return handle(chain, lane, result);
            }),
        });
      },
      getOperation: (value: unknown) =>
        activity(async () => {
          const request = exactClientRecord(
            value,
            ["chain", "id"],
            "owner operation recovery",
            new WeakSet(),
          );
          const chain = chainFor(request.chain);
          if (typeof request.id !== "string" || !/^0x[0-9a-f]{64}$/u.test(request.id))
            return fail("owner operation id is invalid");
          const lane = keyFor(chain.chainId);
          const journal = await store();
          try {
            const record = await journal.getExact(lane, request.id as `0x${string}`);
            if (!record) return null;
            if (record.value.identity.account !== address)
              return clientFail(
                "oaath_client_state_conflict",
                "saved owner operation account differs",
              );
            return handle(chain, lane, { status: "started", record });
          } finally {
            await journal.close();
          }
        }),
    });
  }
  async function closeWork() {
    await Promise.allSettled([...active]);
    let failed = false;
    for (const operation of [...handles])
      await operation.close().catch(() => {
        failed = true;
      });
    for (const [id, observer] of observers) {
      try {
        await observer.close();
        observers.delete(id);
      } catch {
        failed = true;
      }
    }
    if (adapter && !adapterClosed) {
      try {
        await adapter.close();
        adapterClosed = true;
      } catch {
        failed = true;
      }
    }
    database?.close();
    database = undefined;
    if (failed) clientFail("oaath_client_internal", "owner resources could not all be closed");
  }
  return Object.freeze({
    account,
    close() {
      closed = true;
      closing ??= closeWork().finally(() => {
        closing = null;
      });
      return closing;
    },
  });
}
