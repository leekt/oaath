/** Owner-only existing-account execution. The Operation journal remains the lifecycle owner. */
import { captureDenseArray, captureRecord } from "@oaath/protocol";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { detectKernelAccountDeployment, type KernelReads } from "../kernel/deployment/account.js";
import { ECDSA_VALIDATOR } from "../kernel/deployment/v33.js";
import { captureKeyProfile } from "../kernel/internal.js";
import { type EcdsaWalletClient, ecdsaWalletKey } from "../kernel/key/ecdsa.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import type { KeyProfile } from "../kernel/types.js";
import { createOperationObserver, type OperationObserver } from "../operation-observer.js";
import {
  createOperationRunner,
  type OperationPreparationCapability,
  type OperationStartResult,
  type OperationSubmissionCapability,
} from "../operation-runner.js";
import { routingAddress } from "../routing/capabilities.js";
import { decideExecution } from "../routing/decide.js";
import { prepareSponsoredKernelOperation } from "../routing/sponsorship.js";
import type { OaathExecutionDecision } from "../routing/types.js";
import { OperationStore, type OperationStoreAdapter, type OperationStoreKey } from "../store.js";
import {
  kernelImplementation,
  OAATH_CALLS_REVIEW_VERSION,
  type OaathCallsReviewContract,
} from "./calls-review.js";
import type { OaathChains } from "./chain-descriptors.js";
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
  classifyChainRoutes,
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
import { captureStores, type OaathStoreBackend, type OwnedStores, openStores } from "./stores.js";

interface OwnerChain extends OaathChainCapability {
  readonly reads: KernelReads;
}
/** A backend plus an optional Operation journal adapter. */
export type OaathOwnerStores = OaathStoreBackend & Readonly<{ operations?: OperationStoreAdapter }>;
/**
 * Owner-only execution: `createOAAth` options without `approvals`. No Grant
 * exists; the connected wallet signs each operation.
 */
export interface OaathOwnerOptions {
  /** Plain descriptors build the default Cetane ports; custom capabilities override them. */
  readonly chains: OaathChains<OwnerChain>;
  /** When set, `account(address)` refuses every other address. */
  readonly account?: `0x${string}`;
  /** Omitted: owner-only execution. */
  readonly approvals?: undefined;
  /**
   * Only the Operation journal is used. Defaults to `{ kind: "indexeddb" }`,
   * which fails closed outside a browser; this realm owns close.
   */
  readonly stores?: OaathOwnerStores;
}
/** The versioned call-review contract plus owner-realm facts outside it. */
export interface OaathOwnerCallsReview extends OaathCallsReviewContract {
  readonly signer: "owner";
  /** No Grant exists, so nothing limits calls, expiry or operation count. */
  readonly enforcement: Readonly<{ calls: "none"; expiry: "none"; operationCount: "none" }>;
  /** The full call list was estimated as one operation before this review returned. */
  readonly validation: "estimated";
  /**
   * The full call list fits one operation without signing or reserving its lane.
   * `detail` is transport-specific and outside the review contract.
   */
  readonly capacity: Readonly<{ kind: "single-operation"; detail: unknown }>;
  readonly fallback: Readonly<OaathConnectedEoaFallbackReview> | null;
  readonly paymasterService: Readonly<{ url: string }> | null;
  readonly calls: readonly Readonly<OaathCallInput>[];
  readonly reasons: OaathExecutionDecision["reasons"];
}
/**
 * The account's root owner key: a connected ECDSA wallet (the default), or any
 * `kernelKey(...)` signing profile such as a raw P-256 key. Each send proves it
 * is the account's onchain root owner before it is asked to sign; a key whose
 * root validator exposes no owner onchain (WebAuthn) fails closed.
 */
export type OaathOwnerKey = EcdsaWalletClient | Readonly<KeyProfile>;

/** A key profile carries its public material; a wallet client never does. */
export function captureOwnerKey(value: unknown): Readonly<KeyProfile> {
  let key: Readonly<KeyProfile>;
  try {
    key =
      typeof value === "object" && value !== null && Object.hasOwn(value, "publicMaterial")
        ? captureKeyProfile(value)
        : ecdsaWalletKey({ wallet: value as EcdsaWalletClient, validator: ECDSA_VALIDATOR });
  } catch (error) {
    return mapClientFailure(error, "owner key could not be captured");
  }
  // No WebAuthn root validator is pinned, so no account can prove that owner.
  if (key.kind === "webauthn") return ownerKeyUnsupported();
  return key;
}

export function ownerKeyUnsupported(): never {
  return clientFail(
    "oaath_client_capability_unsupported",
    "the owner key kind cannot prove an existing account's root owner",
    "owner_key_kind_unsupported",
  );
}

export interface OaathOwnerHandle {
  readonly reviewCalls: (input: unknown) => Promise<Readonly<OaathOwnerCallsReview>>;
  readonly sendCalls: (input: unknown) => Promise<Readonly<OaathOperationHandle>>;
}
export interface OaathOwnerAccount {
  readonly address: `0x${string}`;
  readonly owner: (owner: OaathOwnerKey) => Readonly<OaathOwnerHandle>;
  /** Exact saved-operation recovery requires no connected wallet. */
  readonly getOperation: (input: unknown) => Promise<Readonly<OaathOperationHandle> | null>;
}
export interface OaathOwnerClient {
  /**
   * An existing Kernel account of any supported version. Each send detects and
   * proves the account's deployment and root owner onchain.
   */
  readonly account: (address: `0x${string}`) => Readonly<OaathOwnerAccount>;
  readonly close: () => Promise<void>;
}

const OWNER_STORES = Object.freeze(["operations"] as const);
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
    ["chains", ...["account", "approvals", "stores"].filter((key) => Object.hasOwn(captured, key))],
    "owner configuration",
    new WeakSet(),
  );
  if (config.approvals !== undefined) return fail("owner-only execution takes no approvals");
  const configuredAccount =
    config.account === undefined ? null : routingAddress(config.account, "owner account", fail);
  const entries = captureDenseArray(config.chains, "owner chains", new WeakSet(), fail);
  if (entries.length < 1 || entries.length > 32)
    return fail("owner chains must hold 1 to 32 entries");
  const chains = new Map<number, Readonly<OwnerChain>>();
  for (const entry of entries) {
    const chain = captureChainCapability(entry) as Readonly<OwnerChain>;
    if (chains.has(chain.chainId)) return fail("owner chains repeat a chain");
    chains.set(chain.chainId, chain);
  }
  const storeSetting = captureStores(config.stores, OWNER_STORES);
  let adapter: OperationStoreAdapter | undefined = storeSetting.overrides.operations;
  let storeOwner: Readonly<OwnedStores<"operations">> | undefined;
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
    opening ??= openStores(storeSetting, OWNER_STORES).then(
      (owner) => {
        storeOwner = owner;
        adapter = owner.stores.operations;
        return adapter;
      },
      (error) => {
        opening = undefined;
        throw error;
      },
    );
    return opening;
  }
  async function store(): Promise<OperationStore> {
    const port = await storage();
    return new OperationStore({
      get: (key) => port.get(key),
      getArchived: (key) => port.getArchived(key),
      list: (scope) => port.list(scope),
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
    if (configuredAccount !== null && address !== configuredAccount)
      return clientFail("oaath_client_state_conflict", "owner client belongs to another account");
    // This is an operation lane label only. No Grant or permission is created.
    const contextId = `owner:kernel:${address}`;
    const keyFor = (chainId: number) =>
      Object.freeze({ grantId: contextId, chainId, kind: "execution" as const });
    return Object.freeze({
      address,
      owner(owner: OaathOwnerKey): Readonly<OaathOwnerHandle> {
        assertOpen();
        const key = captureOwnerKey(owner);
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
            ? capturePaymasterService(request.paymasterService, chain.sponsorship, context)
            : null;
          const deployment = await detectKernelAccountDeployment({
            chainId: chain.chainId,
            address,
            reads: chain.reads,
          });
          assertOpen();
          const runtime = createKernelRuntime({
            deployment,
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
          const routes = await classifyChainRoutes(
            chain.chainId,
            // Owner-realm sends use only a bundler route; its fallback is the connected EOA.
            {
              ...chain,
              routes: (chain.routes ?? []).filter((route) => route.kind === "erc4337-bundler"),
            },
            runtime.deployment.entryPoint.address,
            TIMEOUT,
          );
          const decision = decideExecution({
            operationKind: "execution",
            signer: "owner",
            sessionCoverage: "uncovered",
            routes,
          });
          if (decision.route !== "erc4337-bundler")
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
              nonceKey: "0",
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
                version: OAATH_CALLS_REVIEW_VERSION,
                enforcement: Object.freeze({
                  calls: "none" as const,
                  expiry: "none" as const,
                  operationCount: "none" as const,
                }),
                validation: "estimated" as const,
                capacity: Object.freeze({
                  kind: "single-operation" as const,
                  detail: Object.freeze({
                    callGasLimit: estimated.userOperation.callGasLimit,
                    verificationGasLimit: estimated.userOperation.verificationGasLimit,
                    preVerificationGas: estimated.userOperation.preVerificationGas,
                  }),
                }),
                chainId: resolved.chain.chainId,
                fallback: connectedEoaReview(resolved.feePayer),
                account: Object.freeze({
                  address,
                  implementation: kernelImplementation(resolved.runtime.deployment.kernelVersion),
                }),
                calls: resolved.calls,
                signer: "owner" as const,
                route: resolved.decision.route,
                reasons: resolved.decision.reasons,
                paymasterService:
                  resolved.sponsorship === null || resolved.chain.sponsorship?.kind !== "erc7677"
                    ? null
                    : Object.freeze({ url: resolved.chain.sponsorship.url }),
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
                    route: "erc4337-bundler" as const,
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
    await storeOwner?.close();
    storeOwner = undefined;
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
