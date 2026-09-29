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
import type { PreparedUserOperation } from "../../prepared-user-operation.js";
import { captureInput, exactCaptured, inputInvalid, runtimeFail } from "../internal.js";
import { exactKernelDeployment } from "../modules.js";
import type { KernelDeployment } from "./profile.js";
import {
  bindKernelV33Account,
  createKernelV33Reads,
  type KernelV33AccountDescriptor,
  type KernelV33Deployment,
  type KernelV33ReadRequest,
  kernelV33Deployment,
} from "./v33.js";
import { prepareKernelV33UserOperation } from "./v33-operation.js";

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

export type BindKernelAccountInput = BindExistingKernelAccountInput | BindDerivedKernelAccountInput;

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
 * unavailable evidence never selects another version.
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
  const record = exactCaptured(
    captured,
    [
      "chainId",
      "reads",
      ...(derived ? ["initialPackages", "accountIndex"] : ["address"]),
      ...(Object.hasOwn(captured, "deployment") ? ["deployment"] : []),
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
