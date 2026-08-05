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
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
  createOAAth,
  ecdsaKey,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelV4AccountReadRequest,
  kernelV4Deployment,
  type Oaath,
  type OaathChainCapability,
  type PreparedUserOperation,
} from "../../src/index.js";

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

function relayKms(): RelayKms {
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
export function createRelay(clock: SecondsClock): (request: Request) => Promise<Response> {
  return createRelayHandler({
    store: createMemoryRelayStore(),
    authentication: relayAuthentication(),
    kms: relayKms(),
    clock: { now: () => clock.now() * 1_000 },
  });
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
 * The owner console: it reads the reviewed scope from the relay and posts the
 * terminal decision, exactly as a separate owner device would.
 */
export function createOwnerAuthorization(
  relay: (request: Request) => Promise<Response>,
  clock: SecondsClock,
  options: OwnerDecision = {},
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
        const decision: Record<string, unknown> =
          options.outcome === "reject"
            ? {
                version: OAATH_PERMISSION_DECISION_VERSION,
                kind: "reject",
                requestId: request.requestId,
                requestHash: hashPermissionRequest(full),
                decidedAt: clock.now(),
              }
            : {
                version: OAATH_PERMISSION_DECISION_VERSION,
                kind: "approve",
                requestId: request.requestId,
                requestHash: hashPermissionRequest(full),
                decidedAt: clock.now(),
                approvedPolicy: options.policy ? options.policy(scope.policy) : scope.policy,
                capabilityHash: CAPABILITY_HASH,
              };
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

function runtimeCodeHash(address: `0x${string}`): `0x${string}` {
  if (address === KERNEL_V4_ENTRY_POINT_V07) return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  if (address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
    return deployment.implementationDeployment.runtimeCodeHash;
  }
  return KERNEL_V4_FACTORY_V07_CODE_HASH;
}

export interface ChainFixtureOptions {
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
  /** Withholds inclusion evidence, leaving the operation pending. */
  readonly withholdReceipt?: () => boolean;
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
  const fixture = {
    sends,
    signatures,
    quotes: 0,
  };

  function submitted(): Readonly<PreparedUserOperation> | undefined {
    return sends[sends.length - 1];
  }

  function receipt(hash: `0x${string}`): unknown {
    const prepared = submitted();
    if (!prepared || prepared.userOperationHash !== hash) return null;
    if (options.withholdReceipt?.()) return null;
    const nonce = BigInt(prepared.userOperation.nonce);
    return {
      userOperationHash: hash,
      entryPoint: prepared.entryPoint.address,
      sender: prepared.userOperation.sender,
      nonce: quantity(nonce),
      paymaster: ZERO_ADDRESS,
      actualGasCost: "0x9",
      actualGasUsed: "0xa",
      success: true,
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(INCLUSION_BLOCK),
      blockHash: BLOCK_HASH,
    };
  }

  function transactionReceipt(): unknown {
    const prepared = submitted();
    if (!prepared) return null;
    const nonce = BigInt(prepared.userOperation.nonce);
    return {
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(INCLUSION_BLOCK),
      blockHash: BLOCK_HASH,
      transactionIndex: "0x0",
      status: "0x1",
      logs: [
        {
          address: prepared.entryPoint.address,
          blockNumber: quantity(INCLUSION_BLOCK),
          blockHash: BLOCK_HASH,
          transactionHash: TRANSACTION_HASH,
          transactionIndex: "0x0",
          logIndex: "0x0",
          removed: false,
          topics: [
            EVENT_TOPIC,
            prepared.userOperationHash,
            `0x${"0".repeat(24)}${prepared.userOperation.sender.slice(2)}`,
            `0x${"0".repeat(24)}${ZERO_ADDRESS.slice(2)}`,
          ],
          data: `0x${word(nonce)}${word(1n)}${word(9n)}${word(10n)}`,
        },
      ],
    };
  }

  const inclusionBlock = {
    number: quantity(INCLUSION_BLOCK),
    hash: BLOCK_HASH,
    parentHash: PARENT_HASH,
    transactions: [TRANSACTION_HASH],
  };

  const capability: Readonly<OaathChainCapability> = Object.freeze({
    chainId: CHAIN_ID,
    reads: Object.freeze({
      async read(request: KernelV4AccountReadRequest): Promise<unknown> {
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "runtime_code_hash") return runtimeCodeHash(request.address);
        if (request.type === "code") return request.address === ACCOUNT ? "0x" : "0x01";
        if (request.type === "kernel_factory_implementation") {
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        }
        if (request.type === "kernel_factory_account") return ACCOUNT;
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      },
    }),
    observation: Object.freeze({
      async read(request: { readonly type: string; readonly userOperationHash?: `0x${string}` }) {
        if (request.type === "chain_id") return CHAIN_ID;
        if (request.type === "user_operation_receipt") {
          return receipt(request.userOperationHash ?? `0x${"00".repeat(32)}`);
        }
        if (request.type === "replacement_candidate") return null;
        if (request.type === "transaction_receipt") return transactionReceipt();
        if (request.type === "transaction") {
          const prepared = submitted();
          return prepared
            ? {
                hash: TRANSACTION_HASH,
                to: prepared.entryPoint.address,
                blockNumber: quantity(INCLUSION_BLOCK),
                blockHash: BLOCK_HASH,
                transactionIndex: "0x0",
              }
            : null;
        }
        // Finality equals inclusion, so no ancestor walk is needed.
        if (request.type === "finalized_block" || request.type === "canonical_block") {
          return inclusionBlock;
        }
        if (request.type === "block_by_hash") return inclusionBlock;
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
      if (request.chainId !== CHAIN_ID) throw new Error("unexpected quote chain");
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
  readonly keys: ReturnType<typeof createMemoryKeyStore>;
  readonly cleanup: ReturnType<typeof createMemoryCleanupStore>;
  readonly context: ReturnType<typeof createMemoryContextStore>;
}

export function createMemoryStores(): RealmStores {
  return {
    grants: createMemoryGrantStoreAdapter(),
    operations: createMemoryOperationStoreAdapter(),
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

export interface RealmOptions {
  readonly clock?: SecondsClock;
  readonly relay?: (request: Request) => Promise<Response>;
  readonly stores?: RealmStores;
  readonly chain?: ChainFixture;
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
  const chain = options.chain ?? createChainFixture();
  const owner = createOwnerAuthorization(relay, clock, options.owner ?? {});
  let signOuts = 0;
  let invalidations = 0;

  const oaath = createOAAth({
    binding: bindingInput,
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
    chains: [chain.capability],
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
