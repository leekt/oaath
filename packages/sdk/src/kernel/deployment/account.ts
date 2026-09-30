/**
 * The version-agnostic Kernel account entry points. Kernel version and
 * EntryPoint version are optional settings: a deployment is selected with
 * defaults, an existing account's deployment is detected from its onchain
 * implementation, and an explicit deployment that disagrees with the account
 * fails with `kernel_runtime_deployment_mismatch` before anything is signed. It
 * never silently switches versions. Each version's evidence rules stay owned by
 * its own binder (`kernel-v4.ts`, `v33.ts`); this module only selects one.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  bindKernelV4Account,
  bindKernelV4ExistingAccount,
  createKernelV4Reads,
  encodeKernelV4NonceKey,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelInstall,
  type KernelV4AccountDescriptor,
  type KernelV4AccountReadRequest,
  type KernelV4Deployment,
  type KernelV4ExistingAccountDescriptor,
  type KernelV4ReadClient,
  type KernelV4UserOperationInput,
  type KernelV4ValidationMode,
  type KernelValidation,
  kernelV4Deployment,
  prepareKernelV4UserOperation,
} from "../../kernel-v4.js";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
} from "../../prepared-user-operation.js";
import {
  captureInput,
  exactCaptured,
  exactInput,
  inputCapability,
  inputInvalid,
  inputUint,
  runtimeFail,
} from "../internal.js";
import { exactKernelDeployment } from "../modules.js";
import type { KernelDeployment } from "./profile.js";
import {
  bindDerivedKernelV33Account,
  bindKernelV33Account,
  createKernelV33Reads,
  deriveKernelV33Account,
  type KernelV33AccountDescriptor,
  type KernelV33Deployment,
  type KernelV33Derivation,
  type KernelV33ReadRequest,
  kernelV33Deployment,
} from "./v33.js";
import {
  encodeKernelV33NonceKey,
  kernelV33OperationSigningHash,
  prepareKernelV33UserOperation,
} from "./v33-operation.js";

export type KernelVersion = KernelDeployment["kernelVersion"];
export type KernelEntryPointVersion = KernelDeployment["entryPoint"]["version"];

export interface KernelDeploymentInput {
  readonly chainId: number;
  /** Defaults to the current Kernel release, `"0.4.0"`. */
  readonly kernelVersion?: KernelVersion;
  /** Defaults to the only EntryPoint every supported Kernel version uses, `"0.7"`. */
  readonly entryPoint?: KernelEntryPointVersion;
}

function deploymentFor(chainId: unknown, version: unknown): Readonly<KernelDeployment> {
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1)
    return inputInvalid("Kernel chain ID is invalid");
  if (version === "0.3.3") return kernelV33Deployment(chainId);
  if (version === "0.4.0") return kernelV4Deployment(chainId);
  return inputInvalid("Kernel version is unsupported");
}

/** Selects one reviewed deployment profile; every omitted setting takes its default. */
export function kernelDeployment(
  value: KernelDeploymentInput & { readonly kernelVersion: "0.3.3" },
): Readonly<KernelV33Deployment>;
export function kernelDeployment(
  value: KernelDeploymentInput & { readonly kernelVersion?: "0.4.0" },
): Readonly<KernelV4Deployment>;
export function kernelDeployment(value: KernelDeploymentInput): Readonly<KernelDeployment>;
export function kernelDeployment(value: KernelDeploymentInput): Readonly<KernelDeployment> {
  const captured = captureInput(value, "Kernel deployment selection", new WeakSet());
  const record = exactCaptured(
    captured,
    ["chainId", ...["kernelVersion", "entryPoint"].filter((key) => Object.hasOwn(captured, key))],
    "Kernel deployment selection",
  );
  const deployment = deploymentFor(record.chainId, record.kernelVersion ?? "0.4.0");
  if (record.entryPoint !== undefined && record.entryPoint !== deployment.entryPoint.version)
    return inputInvalid("Kernel EntryPoint version is unsupported");
  return deployment;
}

export interface KernelNonceKeyInput {
  readonly deployment: Readonly<KernelDeployment>;
  /** Kernel `0.3.3` supports only `"standard"` and `"enable"`. */
  readonly mode: KernelV4ValidationMode;
  readonly validation: KernelValidation;
  readonly nonceKey: string;
}

/** The canonical decimal uint192 EntryPoint nonce key for the deployment's Kernel version. */
export function encodeKernelNonceKey(value: KernelNonceKeyInput): string {
  const record = exactInput(
    value,
    ["deployment", "mode", "validation", "nonceKey"],
    "Kernel nonce key",
    new WeakSet(),
  );
  const deployment = exactKernelDeployment(record.deployment);
  const key = { mode: record.mode, validation: record.validation, nonceKey: record.nonceKey };
  return deployment.kernelVersion === "0.3.3"
    ? encodeKernelV33NonceKey(key as Parameters<typeof encodeKernelV33NonceKey>[0])
    : encodeKernelV4NonceKey(key as Parameters<typeof encodeKernelV4NonceKey>[0]);
}

export interface ReadKernelLaneSequenceInput {
  /** A bound account; its chain and EntryPoint select the read. */
  readonly account: Readonly<KernelAccountDescriptor>;
  /** Canonical decimal uint192 EntryPoint key from `encodeKernelNonceKey`. */
  readonly key: string;
  readonly reads: KernelReads;
}

/**
 * The next EntryPoint sequence of one nonce lane (`getNonce(account, key)`'s
 * low 64 bits) for `prepareOperation`'s `sequence`. An unavailable read fails
 * with `kernel_runtime_read_unavailable`; a result for another key or a
 * malformed one with `kernel_runtime_evidence_invalid`.
 */
export async function readKernelLaneSequence(value: ReadKernelLaneSequenceInput): Promise<string> {
  const context = new WeakSet();
  const record = exactInput(value, ["account", "key", "reads"], "Kernel lane sequence", context);
  const account = record.account as Readonly<KernelAccountDescriptor>;
  const key = inputUint(record.key, (1n << 192n) - 1n, "Kernel nonce key");
  const read = inputCapability<KernelReads["read"]>(
    exactInput(record.reads, ["read"], "Kernel lane sequence reads", context).read,
    "Kernel lane sequence read",
  );
  let result: unknown;
  try {
    result = await read(
      Object.freeze({
        type: "entry_point_lane_nonce",
        chainId: account.chainId,
        entryPoint: account.entryPoint,
        account: account.account,
        key: key.toString(10),
      }),
    );
  } catch {
    return runtimeFail("kernel_runtime_read_unavailable", "EntryPoint nonce could not be read");
  }
  if (typeof result !== "string" || !/^(?:0|[1-9][0-9]{0,77})$/u.test(result))
    return runtimeFail("kernel_runtime_evidence_invalid", "EntryPoint nonce is malformed");
  const nonce = BigInt(result);
  if (nonce >> 256n !== 0n || nonce >> 64n !== key)
    return runtimeFail("kernel_runtime_evidence_invalid", "EntryPoint nonce names another key");
  return (nonce & ((1n << 64n) - 1n)).toString(10);
}

export interface KernelOperationSigningHashInput {
  readonly deployment: Readonly<KernelDeployment>;
  readonly operation: PreparedUserOperation;
}

/**
 * The digest the deployment's Kernel version verifies for one prepared
 * operation, for an external signer before `encodeVerifiedSignature`. Kernel
 * `0.4.0` verifies the operation's own hash; a Kernel `0.3.3` enable verifies
 * its chain-zero hash. The prepared operation's identity is unchanged.
 */
export function kernelOperationSigningHash(value: KernelOperationSigningHashInput): `0x${string}` {
  const record = exactInput(
    value,
    ["deployment", "operation"],
    "Kernel operation signing hash",
    new WeakSet(),
  );
  const deployment = exactKernelDeployment(record.deployment);
  return deployment.kernelVersion === "0.3.3"
    ? kernelV33OperationSigningHash(record.operation)
    : parsePreparedUserOperation(record.operation).userOperationHash;
}

export type KernelReadRequest = KernelV4AccountReadRequest | KernelV33ReadRequest;

/** One read capability every supported deployment's binding and operations use. */
export interface KernelReads {
  readonly read: (request: KernelReadRequest) => Promise<unknown>;
}

/** Minimal viem-PublicClient-shaped surface: getChainId, getCode, getStorageAt, call. */
export type KernelReadClient = KernelV4ReadClient;

/** Uses a public RPC client for account evidence; no bundler method is called. */
export function createKernelReads(client: KernelReadClient): Readonly<KernelReads> {
  const v4 = createKernelV4Reads(client);
  const v33 = createKernelV33Reads(client);
  return Object.freeze({
    read(request: KernelReadRequest): Promise<unknown> {
      switch (request.type) {
        case "kernel_account_version":
        case "kernel_account_entrypoint":
        case "kernel_account_root_validator":
        case "kernel_ecdsa_owner":
        case "kernel_v33_factory_approval":
        case "kernel_v33_permission_nonce":
        case "kernel_v33_permission_state":
          return v33.read(request);
        default:
          return v4.read(request as KernelV4AccountReadRequest);
      }
    },
  });
}

export type KernelAccountDescriptor =
  | KernelV33AccountDescriptor
  | KernelV4AccountDescriptor
  | KernelV4ExistingAccountDescriptor;

interface BindKernelAccountCommon {
  readonly chainId: number;
  readonly reads: KernelReads;
  /**
   * Optional expected deployment. Omitted: detected from the account. Given: the
   * account must match it, or binding fails with
   * `kernel_runtime_deployment_mismatch`.
   */
  readonly deployment?: Readonly<KernelDeployment>;
}

/** A deployed account at its existing address; the deployment is detected. */
export interface BindExistingKernelAccountInput extends BindKernelAccountCommon {
  readonly address: `0x${string}`;
}

/**
 * A counterfactual or deployed account derived from its initial packages and
 * index through the deployment's factory. Only Kernel `0.4.0` derives accounts.
 */
export interface BindDerivedKernelAccountInput extends BindKernelAccountCommon {
  readonly initialPackages: readonly KernelInstall[];
  readonly accountIndex: string;
}

/**
 * A counterfactual or deployed Kernel `0.3.3` account derived from its ECDSA
 * root owner and index through the deployment's MetaFactory route, at the
 * address ZeroDev's SDK derives. The deployment is required.
 */
export interface BindEcdsaOwnerKernelAccountInput extends BindKernelAccountCommon {
  readonly deployment: Readonly<KernelDeployment>;
  readonly owner: `0x${string}`;
  readonly accountIndex: string;
}

export type BindKernelAccountInput =
  | BindExistingKernelAccountInput
  | BindDerivedKernelAccountInput
  | BindEcdsaOwnerKernelAccountInput;

export interface DeriveKernelAccountInput {
  /** Only Kernel `0.3.3` derives offline; Kernel `0.4.0` derives through factory reads. */
  readonly deployment: Readonly<KernelDeployment>;
  readonly owner: `0x${string}`;
  readonly accountIndex: string;
}

/** The account address and the EntryPoint 0.7 `factory` / `factoryData` that deploy it. */
export type KernelAccountDerivation = KernelV33Derivation;

/**
 * Offline derivation of an ECDSA-owned account through the deployment's
 * MetaFactory route. It reads nothing and proves no chain state; binding does.
 */
export function deriveKernelAccount(
  value: DeriveKernelAccountInput,
): Readonly<KernelAccountDerivation> {
  const record = exactInput(
    value,
    ["deployment", "owner", "accountIndex"],
    "Kernel account derivation",
    new WeakSet(),
  );
  if (exactKernelDeployment(record.deployment).kernelVersion !== "0.3.3")
    return runtimeFail(
      "kernel_runtime_unsupported",
      "Only Kernel 0.3.3 accounts are derived offline from an owner",
    );
  return deriveKernelV33Account(record);
}

function deploymentMismatch(): never {
  return runtimeFail(
    "kernel_runtime_deployment_mismatch",
    "Kernel account does not use the requested deployment",
  );
}

/** Reads which supported implementation an existing account runs; never guesses. */
async function detectKernelVersion(
  read: KernelReads["read"],
  chainId: number,
  account: `0x${string}`,
): Promise<KernelVersion> {
  let implementation: unknown;
  try {
    implementation = await read(
      Object.freeze({ type: "kernel_account_implementation", chainId, account }),
    );
  } catch {
    return runtimeFail(
      "kernel_runtime_read_unavailable",
      "Kernel account implementation could not be read",
    );
  }
  if (implementation === kernelV33Deployment(chainId).implementation) return "0.3.3";
  if (implementation === KERNEL_V4_UUPS_IMPLEMENTATION_V07) return "0.4.0";
  return runtimeFail(
    "kernel_runtime_binding_mismatch",
    "Kernel account implementation is not a supported Kernel deployment",
  );
}

/**
 * Detects an existing account's deployment from one implementation read. It
 * proves nothing else: binding still proves the full deployment evidence.
 */
export async function detectKernelAccountDeployment(
  value: Readonly<{ chainId: number; address: `0x${string}`; reads: KernelReads }>,
): Promise<Readonly<KernelDeployment>> {
  return deploymentFor(
    value.chainId,
    await detectKernelVersion(value.reads.read, value.chainId, value.address),
  );
}

/**
 * Binds one Kernel account on one chain and proves it against its deployment.
 * It never creates an account, changes an owner or authorizes an operation, and
 * unavailable evidence never selects another version. A counterfactual
 * descriptor's operations carry its factory deployment.
 */
export function bindKernelAccount(
  value: BindDerivedKernelAccountInput,
): Promise<Readonly<KernelV4AccountDescriptor>>;
export function bindKernelAccount(
  value: BindKernelAccountInput,
): Promise<Readonly<KernelAccountDescriptor>>;
export async function bindKernelAccount(
  value: BindKernelAccountInput,
): Promise<Readonly<KernelAccountDescriptor>> {
  const captured = captureInput(value, "Kernel account binding", new WeakSet());
  const derived = Object.hasOwn(captured, "initialPackages");
  const ownerDerived = Object.hasOwn(captured, "owner");
  const record = exactCaptured(
    captured,
    [
      "chainId",
      "reads",
      ...(derived
        ? ["initialPackages", "accountIndex"]
        : ownerDerived
          ? ["owner", "accountIndex", "deployment"]
          : ["address"]),
      ...(!ownerDerived && Object.hasOwn(captured, "deployment") ? ["deployment"] : []),
    ],
    "Kernel account binding",
  );
  const chainId = deploymentFor(record.chainId, "0.4.0").chainId;
  const expected =
    record.deployment === undefined ? null : exactKernelDeployment(record.deployment);
  if (expected && expected.chainId !== chainId) return deploymentMismatch();
  const reads = captureInput(record.reads, "Kernel account reads", new WeakSet());
  const read = reads.read;
  if (typeof read !== "function") return inputInvalid("Kernel account read capability is invalid");
  const capability = Object.freeze({ read: read as KernelReads["read"] });
  if (ownerDerived) {
    if (expected?.kernelVersion !== "0.3.3")
      return runtimeFail(
        "kernel_runtime_unsupported",
        "Only Kernel 0.3.3 accounts are derived from an owner",
      );
    return bindDerivedKernelV33Account({
      chainId,
      owner: record.owner as `0x${string}`,
      accountIndex: record.accountIndex as string,
      reads: capability,
    });
  }
  if (derived) {
    if (expected && expected.kernelVersion !== "0.4.0") return deploymentMismatch();
    return bindKernelV4Account({
      chainId,
      initialPackages: record.initialPackages as readonly KernelInstall[],
      accountIndex: record.accountIndex as string,
      reads: capability,
    });
  }
  const address = record.address as `0x${string}`;
  const version = await detectKernelVersion(capability.read, chainId, address);
  if (expected && expected.kernelVersion !== version) return deploymentMismatch();
  return version === "0.3.3"
    ? bindKernelV33Account({ chainId, address, reads: capability })
    : bindKernelV4ExistingAccount({ chainId, address, reads: capability });
}

/** The deployment profile a bound account descriptor belongs to. */
export function kernelAccountDeployment(
  account: Readonly<KernelAccountDescriptor>,
): Readonly<KernelDeployment> {
  return account.profile === "kernel-v3.3-entrypoint-v0.7"
    ? kernelV33Deployment(account.chainId)
    : kernelV4Deployment(account.chainId);
}

export interface PrepareKernelUserOperationInput
  extends Omit<KernelV4UserOperationInput, "account" | "nonce"> {
  readonly account: Readonly<KernelAccountDescriptor>;
  readonly nonce: Readonly<{
    /** Kernel `0.3.3` accounts support `standard` and `enable` only. */
    mode: KernelV4ValidationMode | "enable";
    validation: Readonly<KernelValidation>;
    nonceKey: string;
    sequence: string;
  }>;
}

/**
 * Builds and hashes one EntryPoint UserOperation for a bound account, using its
 * own deployment's nonce and execution codecs. It never signs.
 */
export function prepareKernelUserOperation(
  value: PrepareKernelUserOperationInput,
): PreparedUserOperation {
  const record = captureInput(value, "Kernel UserOperation", new WeakSet());
  const account = record.account as Readonly<KernelAccountDescriptor> | undefined;
  let profile: unknown;
  try {
    profile = account?.profile;
  } catch {
    return inputInvalid("Kernel UserOperation account is invalid");
  }
  return profile === "kernel-v3.3-entrypoint-v0.7"
    ? prepareKernelV33UserOperation(record)
    : prepareKernelV4UserOperation(record as unknown as KernelV4UserOperationInput);
}
