/**
 * Browser-client harness.
 *
 * The issuer is the real `@oaath/server` Fetch relay handler running in this
 * process over its in-memory store: the client speaks the wire contract, not a
 * mock of it. Only the chain stays synthetic — reads, bundler probe, submission,
 * quote, and observation evidence are injected fixtures, so no test needs Anvil
 * or a network.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  parseGrantPolicy,
} from "@oaath/protocol";
import {
  createMemoryRelayStore,
  createRelayHandler,
  type RelayAuthentication,
  type RelayCaller,
  type RelayKms,
} from "@oaath/server";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { OaathChainCapability } from "../../src/advanced.js";
import { deriveSessionPolicyProfiles } from "../../src/client/grant-handle.js";
import { createOAAth, type Oaath } from "../../src/index.js";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelAllChainApproval,
  type KernelV4AccountReadRequest,
  kernelAllChainCapabilityHash,
  kernelV4Deployment,
  ownerOperator,
  type PreparedUserOperation,
  sessionOperator,
} from "../../src/kernel.js";
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
  createMemoryWalletCallBundleStoreAdapter,
} from "../../src/testing.js";

export const CHAIN_ID = 421_614;
export const ISSUER_URL = "https://issuer.example";
export const ORIGIN = "https://app.example";
export const REDIRECT_URI = "https://app.example/callback";
export const CLIENT_TOKEN = "client-token";
export const OWNER_TOKEN = "owner-token";
export const SUBJECT = "subject-1";

export const deployment = kernelV4Deployment(CHAIN_ID);
export const VALIDATOR = `0x${"22".repeat(20)}` as const;
export const ACCOUNT = `0x${"66".repeat(20)}` as const;
export const TARGET = `0x${"44".repeat(20)}` as const;
export const SELECTOR = "0xa9059cbb" as const;
export const CALL_DATA = `0x${"a9059cbb"}${"0".repeat(64)}` as const;
export const CAPABILITY_HASH = keccak256(stringToBytes("oaath-test-capability"));

const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const sessionAccount = privateKeyToAccount(`0x${"12".repeat(32)}`);
const ZERO_ADDRESS = `0x${"00".repeat(20)}` as const;
const EVENT_TOPIC = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const BEFORE_EXECUTION_TOPIC =
  "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972" as const;
const INCLUSION_BLOCK = 20n;
const BLOCK_HASH = `0x${"55".repeat(32)}` as const;
const PARENT_HASH = `0x${"aa".repeat(32)}` as const;
const TRANSACTION_HASH = `0x${"44".repeat(32)}` as const;
const KMS_PREFIX = "oaath-sdk-test-kms:v1:";

export const ownerCredential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa" as const,
  address: ownerAccount.address.toLowerCase() as `0x${string}`,
});

export const operatorCredential = Object.freeze({
  version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa" as const,
  address: sessionAccount.address.toLowerCase() as `0x${string}`,
});

export const accountProfile = Object.freeze({
  version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  kind: "kernel" as const,
  accountIndex: "0",
  kernelVersion: "0.4.0" as const,
  factoryRoute: "kernel_factory" as const,
  entryPoint: Object.freeze({ version: "0.7" as const }),
  ownerCredential,
});

export const bindingInput = Object.freeze({
  issuer: ISSUER_URL,
  applicationId: "app-a",
  applicationName: "OAAth Example",
  clientId: "client-a",
  origin: ORIGIN,
  redirectUri: REDIRECT_URI,
  deviceId: "device-a",
  userHandle: "user-1",
  account: accountProfile,
  operatorCredential,
});

export function permissionInput(overrides: Record<string, unknown> = {}): unknown {
  return {
    chainScope: "all",
    permissions: [{ calls: [{ target: TARGET, selectors: [SELECTOR], valueLimit: "0" }] }],
    expiresIn: 1_800,
    perChainOperationLimit: 10,
    ...overrides,
  };
}

export function sendCallsInput(): unknown {
  return {
    chain: CHAIN_ID,
    calls: [{ target: TARGET, value: "0", data: CALL_DATA }],
  };
}

export interface SecondsClock {
  readonly now: () => number;
  readonly advance: (seconds: number) => void;
}

export function createClock(start = 1_800_000_000): SecondsClock {
  let current = start;
  return {
    now: () => current,
    advance: (seconds) => {
      current += seconds;
    },
  };
}

function relayAuthentication(): RelayAuthentication {
  const callers: ReadonlyMap<string, RelayCaller> = new Map([
    [
      CLIENT_TOKEN,
      { role: "client", clientId: "client-a", subject: SUBJECT, redirectUris: [REDIRECT_URI] },
    ],
    [OWNER_TOKEN, { role: "owner", clientId: "owner-console", subject: SUBJECT, redirectUris: [] }],
  ]);
  return {
    async authenticate(request: Request) {
      const header = request.headers.get("authorization") ?? "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
      return callers.get(token) ?? null;
    },
  };
}

export function relayKms(): RelayKms {
  return {
    async encrypt(plaintext: string) {
      return `${KMS_PREFIX}${btoa(plaintext)}`;
    },
    async decrypt(reference: string) {
      if (!reference.startsWith(KMS_PREFIX)) throw new Error("unknown ciphertext reference");
      return atob(reference.slice(KMS_PREFIX.length));
    },
  };
}

/** The relay's own clock is milliseconds; the SDK's protocol clock is seconds. */
export function createRelay(
  clock: SecondsClock,
  options: Record<string, unknown> = {},
): (request: Request) => Promise<Response> {
  return createRelayHandler({
    store: createMemoryRelayStore(),
    authentication: relayAuthentication(),
    kms: relayKms(),
    clock: { now: () => clock.now() * 1_000 },
    ...options,
  });
}

/** Adapts one synthetic chain fixture into the relay's chain execution ports. */
export function relayChainPort(fixture: ChainFixture): Record<string, unknown> {
  const capability = fixture.capability;
  return {
    chainId: capability.chainId,
    reads: (request: unknown) => capability.reads.read(request as never),
    observation: (request: unknown) => capability.observation.read(request as never),
    bundler: (request: unknown) => capability.bundler.probe(request as never),
    quote: (request: unknown) => capability.quote(request as never),
    // One submission settles per call: open, send once, close.
    submission: async (request: unknown) => {
      const session = (await capability.submission.open(request as never)) as {
        readonly send: () => Promise<unknown>;
        readonly close: () => Promise<void>;
      };
      try {
        return await session.send();
      } finally {
        await session.close();
      }
    },
    usage:
      capability.usage === null ? null : (request: unknown) => capability.usage?.(request as never),
    feePayer: capability.feePayer,
  };
}

function authorized(request: Request, token: string): Request {
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${token}`);
  return new Request(request, { headers });
}

export interface OwnerDecision {
  /** `reject` records a terminal rejection instead of an approval. */
  readonly outcome?: "approve" | "reject";
  /** Replaces the approved policy, for attenuation or widening attempts. */
  readonly policy?: (requested: unknown) => unknown;
  /** Replaces the decision envelope entirely, for hostile artifacts. */
  readonly artifact?: (decision: Record<string, unknown>) => unknown;
}

/**
 * Derives the owner's replayable install approval exactly as an owner device
 * would: the account from the owner's own initial packages, the permission
 * packages from the approved policy and the operator credential, and one
 * owner signature over the chain-agnostic install digest.
 */
async function ownerInstallApproval(
  reads: OaathChainCapability["reads"],
  approvedPolicy: unknown,
  operatorAddress: `0x${string}`,
): Promise<Readonly<KernelAllChainApproval>> {
  const owner = ecdsaKey({ account: ownerAccount, validator: VALIDATOR });
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: owner }),
    reads,
  });
  const descriptor = await ownerRuntime.bindAccount({
    accountIndex: "0",
    initialPackages: [...ownerRuntime.packages],
  });
  // The permission packages depend only on the operator's public identity —
  // the credential the owner reviews — never on a signing capability, so the
  // owner derives them independently from the reviewed scope.
  const sessionRuntime = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: ecdsaKey({
        account: { address: operatorAddress, sign: async () => "0x" },
        validator: `0x${"01".repeat(20)}`,
      }),
      policies: deriveSessionPolicyProfiles(parseGrantPolicy(approvedPolicy)),
    }),
    reads,
  });
  return approveKernelPermissionAllChain({
    owner,
    account: descriptor.account,
    installNonce: "0",
    packages: [...sessionRuntime.packages],
  });
}

/**
 * The owner console: it reads the reviewed scope from the relay, derives and
 * signs the replayable install approval, and posts the terminal decision,
 * exactly as a separate owner device would.
 */
export function createOwnerAuthorization(
  relay: (request: Request) => Promise<Response>,
  clock: SecondsClock,
  options: OwnerDecision = {},
  reads: OaathChainCapability["reads"] = createChainFixture().capability.reads,
) {
  const calls: string[] = [];
  return {
    calls,
    capability: {
      async authorize(request: { readonly requestId: string }) {
        calls.push(request.requestId);
        const state = (await (
          await relay(
            authorized(
              new Request(`${ISSUER_URL}/authorization/requests/${request.requestId}`),
              OWNER_TOKEN,
            ),
          )
        ).json()) as { readonly requestedScope: string };
        const scope = JSON.parse(state.requestedScope) as Record<string, unknown>;
        const full = { ...scope, requestId: request.requestId };
        let decision: Record<string, unknown>;
        if (options.outcome === "reject") {
          decision = {
            version: OAATH_PERMISSION_DECISION_VERSION,
            kind: "reject",
            requestId: request.requestId,
            requestHash: hashPermissionRequest(full),
            decidedAt: clock.now(),
          };
        } else {
          const approvedPolicy = options.policy ? options.policy(scope.policy) : scope.policy;
          const operator = scope.operatorCredential as { readonly address: `0x${string}` };
          const installApproval = await ownerInstallApproval(
            reads,
            approvedPolicy,
            operator.address,
          );
          decision = {
            version: OAATH_PERMISSION_DECISION_VERSION,
            kind: "approve",
            requestId: request.requestId,
            requestHash: hashPermissionRequest(full),
            decidedAt: clock.now(),
            approvedPolicy,
            capabilityHash: kernelAllChainCapabilityHash(installApproval),
            installApproval,
          };
        }
        const body = {
          outcome: "approved",
          artifact: JSON.stringify(options.artifact ? options.artifact(decision) : decision),
        };
        const decided = (await (
          await relay(
            authorized(
              new Request(`${ISSUER_URL}/authorization/requests/${request.requestId}/decision`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(body),
              }),
              OWNER_TOKEN,
            ),
          )
        ).json()) as { readonly code?: string; readonly error?: unknown };
        if (typeof decided.code !== "string") {
          throw new Error(`owner decision failed: ${JSON.stringify(decided)}`);
        }
        return { code: decided.code };
      },
    },
  };
}

function quantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function runtimeCodeHash(address: `0x${string}`, selectedDeployment = deployment): `0x${string}` {
  if (address === KERNEL_V4_ENTRY_POINT_V07) return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  if (address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
    return selectedDeployment.implementationDeployment.runtimeCodeHash;
  }
  return KERNEL_V4_FACTORY_V07_CODE_HASH;
}

export interface ChainFixtureOptions {
  readonly chainId?: 46_630 | 421_614 | 11_155_111;
  /** Smart account returned by the synthetic factory; defaults to ACCOUNT. */
  readonly account?: `0x${string}`;
  /**
   * Complete finalized usage evidence enables session coverage. Defaults to
   * true — the golden path is session execution. `false` removes the usage
   * capability, which makes coverage inconclusive and denies sendCalls.
   */
  readonly usage?: boolean;
  readonly bundler?: "available" | "absent" | "unsupported" | "unreadable";
  readonly feePayer?: Readonly<{ address: `0x${string}`; balance: string }> | null;
  /** Injected crash inside the send boundary, after the transport accepted it. */
  readonly crashOnSend?: () => boolean;
  /**
   * Answers the `kernel_permission_installed` observation read: `false` means
   * the permission's signer module is conclusively absent (removed), `true`
   * still installed, `null`/absent no conclusive answer.
   */
  readonly permissionInstalled?: () => boolean | null;
  /**
   * Extra blocks the chain advanced beyond its submissions — e.g. an owner
   * console's out-of-band removal transaction.
   */
  readonly blockOffset?: () => number;
  /** Withholds inclusion evidence, leaving the operation pending. */
  readonly withholdReceipt?: () => boolean;
  /** UserOperation execution result by submission index; validation still succeeded. */
  readonly operationSuccess?: (submissionIndex: number) => boolean;
  /**
   * Serves the EntryPoint nonce for the supersession read: given the
   * operation's own nonce, return the observed one, or null for no answer.
   */
  readonly entryPointNonce?: (operationNonce: string) => string | null;
  /** The account's on-chain sequence when this fixture starts observing. */
  readonly startSequence?: number;
}

export interface ChainFixture {
  readonly capability: Readonly<OaathChainCapability>;
  /** Every snapshot handed to the submission transport, in order. */
  readonly sends: Readonly<PreparedUserOperation>[];
  readonly signatures: string[];
  readonly quotes: number;
}

/**
 * One synthetic chain: account reads, a bundler probe, a submission transport
 * that records exactly what it was handed, and canonical inclusion and finality
 * evidence for whatever identity was actually submitted.
 */
export function createChainFixture(options: ChainFixtureOptions = {}): ChainFixture {
  const sends: Readonly<PreparedUserOperation>[] = [];
  const signatures: string[] = [];
  const chainId = options.chainId ?? CHAIN_ID;
  const selectedDeployment = kernelV4Deployment(chainId);
  const account = options.account ?? ACCOUNT;
  const fixture = {
    sends,
    signatures,
    quotes: 0,
  };

  function submitted(): Readonly<PreparedUserOperation> | undefined {
    return sends[sends.length - 1];
  }

  // One block per submission, so evidence ordering holds the way a real chain
  // guarantees it: an operation's removal evidence always names a later block
  // than the installation it removes. `startSequence` shifts the base the same
  // way it shifts the nonce — a chain resumed later has advanced.
  function blockNumber(index: number): bigint {
    return (
      INCLUSION_BLOCK +
      BigInt((options.startSequence ?? 0) + (options.blockOffset?.() ?? 0) + index)
    );
  }

  function blockHash(index: number): `0x${string}` {
    const shifted = (options.startSequence ?? 0) + (options.blockOffset?.() ?? 0) + index;
    if (shifted < 0) return PARENT_HASH;
    return `${BLOCK_HASH.slice(0, -2)}${(shifted % 256).toString(16).padStart(2, "0")}` as `0x${string}`;
  }

  function currentIndex(): number {
    return Math.max(0, sends.length - 1);
  }

  function receipt(hash: `0x${string}`): unknown {
    const prepared = submitted();
    if (!prepared || prepared.userOperationHash !== hash) return null;
    if (options.withholdReceipt?.()) return null;
    const success = options.operationSuccess?.(currentIndex()) ?? true;
    const nonce = BigInt(prepared.userOperation.nonce);
    return {
      userOperationHash: hash,
      entryPoint: prepared.entryPoint.address,
      sender: prepared.userOperation.sender,
      nonce: quantity(nonce),
      paymaster: ZERO_ADDRESS,
      actualGasCost: "0x9",
      actualGasUsed: "0xa",
      success,
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(blockNumber(currentIndex())),
      blockHash: blockHash(currentIndex()),
    };
  }

  function transactionReceipt(): unknown {
    const prepared = submitted();
    if (!prepared) return null;
    const nonce = BigInt(prepared.userOperation.nonce);
    const success = options.operationSuccess?.(currentIndex()) ?? true;
    return {
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(blockNumber(currentIndex())),
      blockHash: blockHash(currentIndex()),
      transactionIndex: "0x0",
      status: "0x1",
      gasUsed: "0x2a",
      logs: [
        {
          address: prepared.entryPoint.address,
          blockNumber: quantity(blockNumber(currentIndex())),
          blockHash: blockHash(currentIndex()),
          transactionHash: TRANSACTION_HASH,
          transactionIndex: "0x0",
          logIndex: "0x0",
          removed: false,
          topics: [BEFORE_EXECUTION_TOPIC],
          data: "0x",
        },
        {
          address: prepared.entryPoint.address,
          blockNumber: quantity(blockNumber(currentIndex())),
          blockHash: blockHash(currentIndex()),
          transactionHash: TRANSACTION_HASH,
          transactionIndex: "0x0",
          logIndex: "0x1",
          removed: false,
          topics: [
            EVENT_TOPIC,
            prepared.userOperationHash,
            `0x${"0".repeat(24)}${prepared.userOperation.sender.slice(2)}`,
            `0x${"0".repeat(24)}${ZERO_ADDRESS.slice(2)}`,
          ],
          data: `0x${word(nonce)}${word(success ? 1n : 0n)}${word(9n)}${word(10n)}`,
        },
      ],
    };
  }

  function inclusionBlock() {
    const index = currentIndex();
    return {
      number: quantity(blockNumber(index)),
      hash: blockHash(index),
      parentHash: blockHash(index - 1),
      transactions: [TRANSACTION_HASH],
    };
  }

  const capability: Readonly<OaathChainCapability> = Object.freeze({
    chainId,
    reads: Object.freeze({
      async read(request: KernelV4AccountReadRequest): Promise<unknown> {
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "runtime_code_hash") {
          return runtimeCodeHash(request.address, selectedDeployment);
        }
        if (request.type === "code") return request.address === account ? "0x" : "0x01";
        if (request.type === "kernel_factory_implementation") {
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        }
        if (request.type === "kernel_factory_account") return account;
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      },
    }),
    observation: Object.freeze({
      async read(request: {
        readonly type: string;
        readonly userOperationHash?: `0x${string}`;
        readonly nonce?: string;
      }) {
        if (request.type === "chain_id") return chainId;
        if (request.type === "user_operation_receipt") {
          return receipt(request.userOperationHash ?? `0x${"00".repeat(32)}`);
        }
        if (request.type === "replacement_candidate") return null;
        if (request.type === "entry_point_nonce") {
          const observed = options.entryPointNonce?.(request.nonce ?? "0") ?? null;
          return observed === null ? null : `0x${BigInt(observed).toString(16)}`;
        }
        if (request.type === "kernel_permission_installed") {
          return options.permissionInstalled?.() ?? null;
        }
        if (request.type === "transaction_receipt") return transactionReceipt();
        if (request.type === "transaction") {
          const prepared = submitted();
          return prepared
            ? {
                hash: TRANSACTION_HASH,
                to: prepared.entryPoint.address,
                blockNumber: quantity(blockNumber(currentIndex())),
                blockHash: blockHash(currentIndex()),
                transactionIndex: "0x0",
              }
            : null;
        }
        // Finality equals inclusion, so no ancestor walk is needed.
        if (request.type === "finalized_block" || request.type === "canonical_block") {
          return inclusionBlock();
        }
        if (request.type === "block_by_hash") return inclusionBlock();
        throw new Error(`unsupported observation read ${request.type}`);
      },
      async close() {},
    }),
    bundler: Object.freeze({
      async probe(request: { readonly chainId: number; readonly entryPoint: `0x${string}` }) {
        const state = options.bundler ?? "available";
        if (state === "unreadable") throw new Error("bundler unreachable");
        return {
          accepting: state !== "absent",
          chainId: state === "unsupported" ? request.chainId + 1 : request.chainId,
          supportedEntryPoints: [request.entryPoint],
        };
      },
    }),
    submission: Object.freeze({
      async open(request: {
        readonly prepared: Readonly<PreparedUserOperation>;
        readonly signature: `0x${string}`;
      }) {
        sends.push(request.prepared);
        signatures.push(request.signature);
        return {
          async send() {
            if (options.crashOnSend?.()) {
              // The transport accepted the operation and the answer never came
              // back. The identity stays exactly as submitted.
              throw new Error("send/return crash");
            }
            return { userOperationHash: request.prepared.userOperationHash };
          },
          async close() {},
        };
      },
    }),
    async quote(request: { readonly chainId: number }) {
      fixture.quotes += 1;
      if (request.chainId !== chainId) throw new Error("unexpected quote chain");
      return {
        nonceKey: "0",
        // The account's next sequence, as a chain read would report it.
        sequence: String((options.startSequence ?? 0) + sends.length),
        gas: {
          callGasLimit: "100000",
          verificationGasLimit: "200000",
          preVerificationGas: "50000",
          maxFeePerGas: "1000000000",
          maxPriorityFeePerGas: "100000000",
        },
      };
    },
    usage:
      options.usage !== false
        ? async (request: Readonly<{ grantId: string; chainId: number }>) => ({
            version: "oaath.grant-policy-usage/v1",
            status: "complete",
            grantId: request.grantId,
            chainId: request.chainId,
            finalizedOperationCount: "0",
            through: {
              blockNumber: INCLUSION_BLOCK.toString(10),
              blockHash: BLOCK_HASH,
              observedAt: 1_800_000_000,
            },
          })
        : null,
    feePayer: options.feePayer ?? null,
  });

  return Object.freeze({
    capability,
    sends,
    signatures,
    get quotes() {
      return fixture.quotes;
    },
  });
}

export interface RealmStores {
  readonly grants: ReturnType<typeof createMemoryGrantStoreAdapter>;
  readonly operations: ReturnType<typeof createMemoryOperationStoreAdapter>;
  readonly walletCallBundles: ReturnType<typeof createMemoryWalletCallBundleStoreAdapter>;
  readonly keys: ReturnType<typeof createMemoryKeyStore>;
  readonly cleanup: ReturnType<typeof createMemoryCleanupStore>;
  readonly context: ReturnType<typeof createMemoryContextStore>;
}

export function createMemoryStores(): RealmStores {
  return {
    grants: createMemoryGrantStoreAdapter(),
    operations: createMemoryOperationStoreAdapter(),
    walletCallBundles: createMemoryWalletCallBundleStoreAdapter(),
    keys: createMemoryKeyStore(),
    cleanup: createMemoryCleanupStore(),
    context: createMemoryContextStore(),
  };
}

export function signingProfiles() {
  return {
    owner: ecdsaKey({ account: ownerAccount, validator: VALIDATOR }),
    session: ecdsaKey({ account: sessionAccount, validator: VALIDATOR }),
  };
}

export interface UrlRealmOptions {
  readonly clock?: SecondsClock;
  readonly chain?: ChainFixture;
  readonly owner?: OwnerDecision;
  /** The service URL the realm connects to; loopback http is a legal default. */
  readonly url?: string;
  /** Shared durable stores, so a second realm simulates a reload. */
  readonly stores?: RealmStores;
  /** Shared relay, so a second realm sees the first realm's issuer state. */
  readonly relay?: (request: Request) => Promise<Response>;
  /** Tampers with the served bootstrap document before the SDK parses it. */
  readonly bootstrap?: (document: Record<string, unknown>) => unknown;
  /** Remote session-key custody the relay declares and serves. */
  readonly sessionSigner?: Readonly<{
    mode: "application_backend" | "oaath_hosted";
    providerId: string;
    provider: unknown;
  }>;
}

export interface UrlRealm {
  readonly oaath: Readonly<Oaath>;
  readonly clock: SecondsClock;
  readonly chain: ChainFixture;
  readonly stores: RealmStores;
  readonly relay: (request: Request) => Promise<Response>;
  readonly invalidations: () => number;
  readonly fetched: readonly string[];
}

/**
 * The URL-only realm against the real relay: the SDK receives one service URL
 * and a client-authenticated transport; identity, account, chains, code
 * pickup, and invalidation all ride the service. The owner console decides
 * out of band as soon as a request is created, exactly like a phone would.
 */
export function createUrlRealm(options: UrlRealmOptions = {}): UrlRealm {
  const clock = options.clock ?? createClock();
  const chain = options.chain ?? createChainFixture();
  const stores = options.stores ?? createMemoryStores();
  const relay =
    options.relay ??
    createRelay(clock, {
      bootstrap: {
        application: {
          applicationId: "app-a",
          applicationName: "OAAth Example",
          clientId: "client-a",
          redirectUris: [REDIRECT_URI],
        },
        userHandle: "user-1",
        account: accountProfile,
        ownerValidator: VALIDATOR,
      },
      chains: [relayChainPort(chain)],
      ...(options.sessionSigner ? { sessionSigner: options.sessionSigner } : {}),
    });
  const owner = createOwnerAuthorization(relay, clock, options.owner ?? {}, chain.capability.reads);
  let invalidations = 0;
  const fetched: string[] = [];

  // The owner decides as soon as the request exists; the SDK's default
  // authorization then finds the released code through pickup polling.
  const service = async (request: Request): Promise<Response> => {
    fetched.push(`${request.method} ${new URL(request.url).pathname}`);
    if (request.method === "POST" && new URL(request.url).pathname === "/invalidations") {
      invalidations += 1;
    }
    if (
      options.bootstrap &&
      request.method === "GET" &&
      new URL(request.url).pathname === "/bootstrap"
    ) {
      const response = await relay(authorized(request, CLIENT_TOKEN));
      const document = (await response.json()) as Record<string, unknown>;
      return new Response(JSON.stringify(options.bootstrap(document)), {
        status: response.status,
        headers: { "content-type": "application/json" },
      });
    }
    const response = await relay(authorized(request, CLIENT_TOKEN));
    if (
      request.method === "POST" &&
      new URL(request.url).pathname === "/authorization/requests" &&
      response.status === 201
    ) {
      const created = (await response.clone().json()) as { readonly requestId: string };
      await owner.capability.authorize({ requestId: created.requestId }).catch(() => undefined);
    }
    return response;
  };

  const oaath = createOAAth({
    url: options.url ?? ISSUER_URL,
    fetch: service,
    origin: ORIGIN,
    stores,
    now: clock.now,
  });

  return { oaath, clock, chain, stores, relay, invalidations: () => invalidations, fetched };
}

export interface RealmOptions {
  readonly clock?: SecondsClock;
  readonly relay?: (request: Request) => Promise<Response>;
  readonly stores?: RealmStores;
  readonly chain?: ChainFixture;
  readonly chains?: readonly ChainFixture[];
  readonly binding?: unknown;
  readonly owner?: OwnerDecision;
  /** Overrides the signing keys, e.g. with keys the binding never approved. */
  readonly signing?: ReturnType<typeof signingProfiles>;
  readonly issuerSignOut?: (() => Promise<unknown>) | null;
  readonly invalidate?: (
    request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
  ) => Promise<unknown>;
}

export interface Realm {
  readonly oaath: Readonly<Oaath>;
  readonly clock: SecondsClock;
  readonly relay: (request: Request) => Promise<Response>;
  readonly stores: RealmStores;
  readonly chain: ChainFixture;
  readonly ownerCalls: readonly string[];
  readonly signOutCalls: () => number;
  readonly invalidations: () => number;
}

/** Composes one realm: real relay, memory stores, and the synthetic chain. */
export function createRealm(options: RealmOptions = {}): Realm {
  const clock = options.clock ?? createClock();
  const relay = options.relay ?? createRelay(clock);
  const stores = options.stores ?? createMemoryStores();
  const chain = options.chain ?? options.chains?.[0] ?? createChainFixture();
  const chains = options.chains ?? [chain];
  const owner = createOwnerAuthorization(relay, clock, options.owner ?? {}, chain.capability.reads);
  let signOuts = 0;
  let invalidations = 0;

  const oaath = createOAAth({
    binding: options.binding ?? bindingInput,
    issuer: {
      url: ISSUER_URL,
      fetch: (request: Request) => relay(authorized(request, CLIENT_TOKEN)),
      signOut:
        options.issuerSignOut === undefined
          ? async () => {
              signOuts += 1;
            }
          : options.issuerSignOut,
    },
    authorization: owner.capability,
    invalidation: {
      invalidateCapability: async (
        request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
      ) => {
        invalidations += 1;
        if (options.invalidate) return options.invalidate(request);
        // A deployment proves the replayable approval capability is dead; the SDK
        // never invents this evidence.
        return {
          evidenceHash: keccak256(stringToBytes(`invalidated:${request.grantId}`)),
          invalidatedAt: clock.now(),
        };
      },
    },
    stores,
    chains: chains.map((entry) => entry.capability),
    signing: options.signing ?? signingProfiles(),
    localKeyIds: ["session-key"],
    now: clock.now,
  });

  return {
    oaath,
    clock,
    relay,
    stores,
    chain,
    ownerCalls: owner.calls,
    signOutCalls: () => signOuts,
    invalidations: () => invalidations,
  };
}
