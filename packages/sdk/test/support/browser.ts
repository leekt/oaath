import { KERNEL_ENTRY_POINT_V07 } from "../../src/kernel/deployment/v33.js";
/**
 * Browser-client harness.
 *
 * Realms compose through the public injected configuration; the owner approves
 * in-process with the replayable install an owner device signs. Only the chain
 * stays synthetic — reads, bundler probe, submission,
 * quote, and observation evidence are injected fixtures, so no test needs Anvil
 * or a network.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  hashPermissionRequest,
  type KernelAccountProfile,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  type OperatorCredentialProfile,
  type PermissionRequest,
  parseGrantPolicy,
  sameOperatorCredentialProfile,
} from "@oaath/protocol";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type {
  OaathBundlerProbeCapability,
  OaathChainCapability,
  OaathChainSponsorship,
  OaathSubmissionRoute,
} from "../../src/advanced.js";
import { deriveOperatorCredentialProfile } from "../../src/client/key-credential.js";
import { createOAAth, type Oaath } from "../../src/index.js";
import {
  KERNEL_P256_VERIFIER,
  KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
} from "../../src/kernel/modules.js";
import {
  type KernelGrantApproval,
  kernelGrantCapabilityHash,
} from "../../src/kernel/permission/approval.js";
import { approveKernelPermissionAllChain } from "../../src/kernel/permission/materialize.js";
import { deriveSessionPolicyProfiles } from "../../src/kernel/permission/profiles.js";
import {
  approveKernelV33Permission,
  kernelV33PermissionInstallNonce,
} from "../../src/kernel/permission/v33.js";
import {
  createKernelRuntime,
  type KeyProfile,
  kernelDeployment,
  kernelKey,
  ownerOperator,
  type PreparedUserOperation,
  sessionOperator,
} from "../../src/kernel.js";
import {
  KERNEL_V4_FACTORY_V09_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V09,
} from "../../src/kernel-v4.js";
import {
  createMemoryCleanupStore,
  createMemoryContextStore,
  createMemoryGrantStoreAdapter,
  createMemoryKeyStore,
  createMemoryOperationStoreAdapter,
  createMemoryPreparedCallStoreAdapter,
  createMemoryWalletCallBundleStoreAdapter,
} from "../../src/persistence/memory/stores.js";

export const CHAIN_ID = 421_614;
export const ISSUER_URL = "https://issuer.example";
export const ORIGIN = "https://app.example";
export const REDIRECT_URI = "https://app.example/callback";
export const CLIENT_TOKEN = "client-token";
export const OWNER_TOKEN = "owner-token";
export const SUBJECT = "subject-1";

export const deployment = kernelDeployment({ chainId: CHAIN_ID });
export const VALIDATOR = `0x${"22".repeat(20)}` as const;
export const ACCOUNT = `0x${"66".repeat(20)}` as const;
export const TARGET = `0x${"44".repeat(20)}` as const;
export const SELECTOR = "0xa9059cbb" as const;
export const CALL_DATA = `0x${"a9059cbb"}${"0".repeat(64)}` as const;
export const CAPABILITY_HASH = keccak256(stringToBytes("oaath-test-capability"));

const ownerAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const sessionAccount = privateKeyToAccount(`0x${"12".repeat(32)}`);
export const SESSION_PUBLIC_KEY = sessionAccount.publicKey.toLowerCase() as `0x${string}`;
export async function signPreparedDigest(hash: `0x${string}`): Promise<`0x${string}`> {
  return (await sessionAccount.sign({ hash })).toLowerCase() as `0x${string}`;
}
const ZERO_ADDRESS = `0x${"00".repeat(20)}` as const;
const EVENT_TOPIC = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f" as const;
const BEFORE_EXECUTION_TOPIC =
  "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972" as const;
const INCLUSION_BLOCK = 20n;
const BLOCK_HASH = `0x${"55".repeat(32)}` as const;
const PARENT_HASH = `0x${"aa".repeat(32)}` as const;
const TRANSACTION_HASH = `0x${"44".repeat(32)}` as const;

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
  entryPoint: Object.freeze({ version: "0.9" as const }),
  ownerCredential,
});

export const workspaceContext = Object.freeze({
  version: "oaath.workspace-account-context/v1",
  workspaceId: "personal-1",
  workspaceKind: "personal",
  accountId: "account-1",
} as const);

export const bindingInput = Object.freeze({
  issuer: ISSUER_URL,
  applicationId: "app-a",
  applicationName: "OAAth Example",
  clientId: "client-a",
  origin: ORIGIN,
  redirectUri: REDIRECT_URI,
  deviceId: "device-a",
  userHandle: "user-1",
  context: workspaceContext,
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

export function bundlerProbe(
  capability: Readonly<OaathChainCapability>,
): OaathBundlerProbeCapability["probe"] {
  const route = capability.routes?.find((entry) => entry.kind === "erc4337-bundler");
  if (route?.kind !== "erc4337-bundler") throw new Error("chain has no bundler route");
  return route.bundler.probe;
}

/** The chain's routes with its bundler probe replaced; order and handleOps stay. */
export function withBundler(
  capability: Readonly<OaathChainCapability>,
  bundler: OaathBundlerProbeCapability,
): readonly OaathSubmissionRoute[] {
  return (capability.routes ?? []).map((route) =>
    route.kind === "erc4337-bundler" ? { kind: route.kind, bundler } : route,
  );
}

/** The handleOps route's fee payer, or null when the chain offers no such route. */
export function routeFeePayer(capability: Readonly<OaathChainCapability>) {
  const route = capability.routes?.find((entry) => entry.kind === "erc4337-handleops");
  return route?.kind === "erc4337-handleops" ? route.feePayer : null;
}

export interface OwnerDecision {
  /** Test-only non-ECDSA operator identity the owner reviewed. */
  readonly operatorKey?: Readonly<KeyProfile>;
}

function ownerApprovedOperatorKey(
  approved: Readonly<OperatorCredentialProfile>,
  supplied: Readonly<KeyProfile> | undefined,
): Readonly<KeyProfile> {
  if (supplied !== undefined) {
    const derived = deriveOperatorCredentialProfile(supplied);
    if (derived === null || !sameOperatorCredentialProfile(derived, approved)) {
      throw new Error("owner fixture operator key does not match the reviewed credential");
    }
    return supplied;
  }
  if (approved.kind !== "ecdsa") {
    throw new Error("owner fixture requires the reviewed non-ECDSA operator key");
  }
  return kernelKey({
    account: { address: approved.address, sign: async () => "0x" },
    // Session composition resolves the pinned signer module and never consults
    // this syntactic validator member.
    validator: `0x${"01".repeat(20)}`,
  });
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
  operatorCredential: Readonly<OperatorCredentialProfile>,
  operatorKey: Readonly<KeyProfile> | undefined,
  validator: `0x${string}`,
  account: Readonly<KernelAccountProfile>,
): Promise<Readonly<KernelGrantApproval>> {
  const owner = kernelKey({ account: ownerAccount, validator });
  if (account.kernelVersion === "0.3.3") {
    const runtime = createKernelRuntime({
      deployment: kernelDeployment({ chainId: CHAIN_ID, kernelVersion: "0.3.3" }),
      operator: sessionOperator({
        key: ownerApprovedOperatorKey(operatorCredential, operatorKey),
        policies: deriveSessionPolicyProfiles(parseGrantPolicy(approvedPolicy)),
      }),
      reads,
    });
    const descriptor = await runtime.bindAccount({ address: account.address });
    const nonce = await kernelV33PermissionInstallNonce({ runtime, account: descriptor, reads });
    return approveKernelV33Permission({ owner, runtime, account: descriptor, nonce });
  }
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
      key: ownerApprovedOperatorKey(operatorCredential, operatorKey),
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

function quantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function runtimeCodeHash(address: `0x${string}`): `0x${string}` {
  if (address === KERNEL_ENTRY_POINT_V07.address) return KERNEL_ENTRY_POINT_V07.runtimeCodeHash;
  if (address === KERNEL_P256_VERIFIER) return KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH;
  if (address === OAATH_KERNEL_V4_VALIDITY_POLICY) {
    return OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH;
  }

  return KERNEL_V4_FACTORY_V09_CODE_HASH;
}

export interface ChainFixtureOptions {
  readonly chainId?: number;
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
  readonly sponsorship?: OaathChainSponsorship;
  /** Injected crash inside the send boundary, after the transport accepted it. */
  readonly crashOnSend?: () => boolean;
  /**
   * Answers the `kernel_permission_installed` observation read: `false` means
   * the permission's signer module is conclusively absent (removed), `true`
   * still installed, `null`/absent no conclusive answer.
   */
  readonly permissionInstalled?: () => boolean | null;
  /** Effective Kernel install nonce at the observation block. Undefined models this fixture's installs. */
  readonly installNonce?: (approvalNonce: string) => string | null;
  /**
   * Extra blocks the chain advanced beyond its submissions — e.g. an owner
   * console's out-of-band removal transaction.
   */
  readonly blockOffset?: () => number;
  /** Withholds inclusion evidence, leaving the operation pending. */
  readonly withholdReceipt?: () => boolean;
  /** Keeps the finalized head one block behind inclusion, leaving the operation included. */
  readonly withholdFinality?: () => boolean;
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
      paymaster: prepared.userOperation.paymaster?.address ?? ZERO_ADDRESS,
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
            `0x${"0".repeat(24)}${(prepared.userOperation.paymaster?.address ?? ZERO_ADDRESS).slice(
              2,
            )}`,
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
      async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]): Promise<unknown> {
        if (request.type === "chain_id") return request.chainId;
        if (request.type === "runtime_code_hash") {
          return runtimeCodeHash(request.address);
        }
        if (request.type === "code") return request.address === account ? "0x" : "0x01";
        if (request.type === "kernel_factory_implementation") {
          return KERNEL_V4_UUPS_IMPLEMENTATION_V09;
        }
        if (request.type === "kernel_factory_account") return account;
        return KERNEL_V4_UUPS_IMPLEMENTATION_V09;
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
          if (options.permissionInstalled) return options.permissionInstalled();
          return submitted()?.kind === "revocation" &&
            !options.withholdReceipt?.() &&
            !options.crashOnSend?.() &&
            (options.operationSuccess?.(currentIndex()) ?? true)
            ? false
            : null;
        }
        if (request.type === "kernel_install_nonce") {
          const nonce = request.nonce ?? "0";
          const observed = options.installNonce
            ? options.installNonce(nonce)
            : (
                BigInt(nonce) + (sends.some((entry) => entry.kind === "execution") ? 1n : 0n)
              ).toString(10);
          return observed === null ? null : `0x${BigInt(observed).toString(16)}`;
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
        // The fixture's finalized head is its canonical inclusion block.
        if (request.type === "finalized_block" && options.withholdFinality?.()) {
          const index = currentIndex() - 1;
          return {
            number: quantity(blockNumber(index)),
            hash: blockHash(index),
            parentHash: blockHash(index - 1),
            transactions: [],
          };
        }
        if (request.type === "finalized_block" || request.type === "canonical_block") {
          return inclusionBlock();
        }
        throw new Error(`unsupported observation read ${request.type}`);
      },
      async close() {},
    }),
    // The bundler + handleOps-fallback configuration: the bundler first, then
    // the handleOps route exactly when a fee payer is configured.
    routes: Object.freeze([
      Object.freeze({
        kind: "erc4337-bundler" as const,
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
      }),
      ...(options.feePayer === undefined || options.feePayer === null
        ? []
        : [Object.freeze({ kind: "erc4337-handleops" as const, feePayer: options.feePayer })]),
    ]),
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
    async quote(request: { readonly chainId: number; readonly nonceKey: string }) {
      fixture.quotes += 1;
      if (request.chainId !== chainId) throw new Error("unexpected quote chain");
      return {
        nonceKey: request.nonceKey,
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
    ...(options.sponsorship === undefined ? {} : { sponsorship: options.sponsorship }),
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
  readonly preparedCallContexts?: ReturnType<typeof createMemoryPreparedCallStoreAdapter>;
  readonly keys: ReturnType<typeof createMemoryKeyStore>;
  readonly cleanup: ReturnType<typeof createMemoryCleanupStore>;
  readonly context: ReturnType<typeof createMemoryContextStore>;
}

export type CompleteRealmStores = RealmStores &
  Readonly<{
    preparedCallContexts: ReturnType<typeof createMemoryPreparedCallStoreAdapter>;
  }>;

export function createMemoryStores(): CompleteRealmStores {
  return {
    grants: createMemoryGrantStoreAdapter(),
    operations: createMemoryOperationStoreAdapter(),
    walletCallBundles: createMemoryWalletCallBundleStoreAdapter(),
    preparedCallContexts: createMemoryPreparedCallStoreAdapter(),
    keys: createMemoryKeyStore(),
    cleanup: createMemoryCleanupStore(),
    context: createMemoryContextStore(),
  };
}

function completeRealmStores(stores: RealmStores): CompleteRealmStores {
  return {
    ...stores,
    preparedCallContexts: stores.preparedCallContexts ?? createMemoryPreparedCallStoreAdapter(),
  };
}

export function signingProfiles(validator: `0x${string}` = VALIDATOR) {
  return {
    owner: kernelKey({ account: ownerAccount, validator }),
    session: kernelKey({ account: sessionAccount, validator }),
  };
}

export interface RealmOptions {
  readonly clock?: SecondsClock;
  readonly stores?: RealmStores;
  readonly chain?: ChainFixture;
  readonly chains?: readonly ChainFixture[];
  readonly binding?: unknown;
  readonly owner?: OwnerDecision;
  /** Replaces the owner's approval artifact before the SDK applies it. */
  readonly claimedArtifact?: (decision: Record<string, unknown>) => unknown;
  /** ECDSA validator deployed by a real local chain fixture. */
  readonly validator?: `0x${string}`;
  /** Overrides the signing keys, e.g. with keys the binding never approved. */
  readonly signing?: ReturnType<typeof signingProfiles>;
  readonly invalidate?: (
    request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
  ) => Promise<unknown>;
}

export interface Realm {
  readonly oaath: Readonly<Oaath>;
  readonly clock: SecondsClock;
  readonly stores: CompleteRealmStores;
  readonly chain: ChainFixture;
  /** Request ids the owner approved, in order. */
  readonly ownerCalls: readonly string[];
  readonly invalidations: () => number;
}

/**
 * The owner's approval as an owner device produces it: the replayable install
 * for the reviewed request, signed by the owner key, as the canonical decision.
 */
export function createOwnerApproval(
  clock: SecondsClock,
  options: OwnerDecision = {},
  reads: OaathChainCapability["reads"] = createChainFixture().capability.reads,
  validator: `0x${string}` = VALIDATOR,
) {
  const calls: string[] = [];
  return {
    calls,
    async approve(request: Readonly<PermissionRequest>): Promise<Record<string, unknown>> {
      calls.push(request.requestId);
      const installApproval = await ownerInstallApproval(
        reads,
        request.policy,
        request.operatorCredential,
        options.operatorKey,
        validator,
        request.logicalAccount,
      );
      return {
        version: OAATH_PERMISSION_DECISION_VERSION,
        kind: "approve",
        requestId: request.requestId,
        requestHash: hashPermissionRequest(request),
        decidedAt: clock.now(),
        approvedPolicy: request.policy,
        capabilityHash: kernelGrantCapabilityHash(installApproval),
        installApproval,
      };
    },
  };
}

/** Composes one realm: the owner's in-process approval, memory stores, and the synthetic chain. */
export function createRealm(options: RealmOptions = {}): Realm {
  const clock = options.clock ?? createClock();
  const stores = completeRealmStores(options.stores ?? createMemoryStores());
  const chain = options.chain ?? options.chains?.[0] ?? createChainFixture();
  const chains = options.chains ?? [chain];
  const validator = options.validator ?? VALIDATOR;
  const owner = createOwnerApproval(clock, options.owner ?? {}, chain.capability.reads, validator);
  let invalidations = 0;

  const oaath = createOAAth({
    binding: (options.binding ?? bindingInput) as typeof bindingInput,
    // The owner's decision, signed in-process as an owner device would.
    async approve(request) {
      const decision = await owner.approve(request);
      return options.claimedArtifact ? options.claimedArtifact(decision) : decision;
    },
    invalidation: {
      invalidateCapability: async (
        request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
      ) => {
        invalidations += 1;
        if (options.invalidate) return options.invalidate(request);
        // Admission evidence; chain effect reads must still prove revocation.
        return {
          evidenceHash: keccak256(stringToBytes(`invalidated:${request.grantId}`)),
          invalidatedAt: clock.now(),
        };
      },
    },
    stores,
    chains: chains.map((entry) => entry.capability),
    signing: options.signing ?? signingProfiles(validator),
    localKeyIds: ["session-key"],
    now: clock.now,
  });

  return {
    oaath,
    clock,
    stores,
    chain,
    ownerCalls: owner.calls,
    invalidations: () => invalidations,
  };
}
