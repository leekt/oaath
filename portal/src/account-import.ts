/**
 * Reading an existing Kernel v4 account before it is imported: whether the
 * signed-in signer is its root, and every module installed on it.
 *
 * Every read goes through the portal's own budgeted `/rpc/421614` proxy. The
 * checks stop at the first failure with a plain explanation. The inventory
 * fingerprint is what the root acknowledges when it signs the import
 * (`signAccountImport`), so it commits to the account, the root, the coverage
 * and every module outside OAAth. The relay records what the root signed; it
 * reads no chain itself.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  captureAddress,
  hashOwnerCredentialProfile,
  type OwnerCredentialProfile,
} from "@oaath/protocol";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import {
  createKernelRuntime,
  ECDSA_VALIDATOR,
  type KernelModuleSnapshot,
  kernelDeployment,
  kernelKey,
  OaathKernelRuntimeError,
  ownerOperator,
  pinnedPolicyModule,
  pinnedSignerModule,
  readKernelModules,
} from "@oaath/sdk/kernel";
import { createPublicClient, http } from "cetane";
import { hashTypedData, keccak256, toHex } from "cetane/utils";
import type { ImportAccountRequest } from "./api.js";
import { rootKey } from "./root-signing.js";
import type { RememberedSigner } from "./signers.js";

export const IMPORT_CHAIN_ID = 421_614;
export const IMPORT_NETWORK = "Arbitrum Sepolia";
/** Hard caps for one inspection: account checks, then module discovery. */
const CHECK_REQUESTS = 32;
const INVENTORY_BUDGET = { maxRequests: 96, timeout: 8_000 };
const TIMEOUT_MS = 8_000;
const ZERO = `0x${"00".repeat(20)}`;

export type ImportCheckId = "address" | "deployed" | "implementation" | "root" | "owner";

export interface ImportCheck {
  readonly id: ImportCheckId;
  readonly label: string;
  readonly status: "pass" | "fail" | "unknown";
  readonly detail: string;
}

/** Root: the account's root validation. OAAth: a permission OAAth issued. Outside: anything else. */
export type ModuleOrigin = "root" | "oaath" | "outside";

export interface InventoryModule {
  readonly moduleType: number;
  readonly module: `0x${string}`;
  readonly label: string;
  readonly origin: ModuleOrigin;
  /** How many installs of this module the origin holds. */
  readonly count: number;
  /** `history`: seen in install events but not confirmed in state. */
  readonly evidence: "state" | "history";
}

export interface AccountInventory {
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly blockNumber: string;
  readonly root: `0x${string}`;
  readonly modules: readonly InventoryModule[];
  readonly outside: number;
  readonly complete: boolean;
  readonly note: string | null;
  readonly fingerprint: `0x${string}`;
}

export interface AccountInspection {
  readonly checks: readonly ImportCheck[];
  readonly compatible: boolean;
  readonly inventory: AccountInventory | null;
  /** Set when the account is compatible but its modules could not be read. */
  readonly inventoryError: string | null;
}

const LABELS: Readonly<Record<ImportCheckId, string>> = {
  address: "Account address",
  deployed: "Deployed account",
  implementation: "Kernel v4 implementation",
  root: "Root validator",
  owner: "Root owner",
};

const MODULE_TYPES: Readonly<Record<number, string>> = {
  1: "validator",
  2: "executor",
  3: "fallback handler",
  5: "policy",
  6: "signer",
  11: "execution hook",
};

const COVERAGE_NOTES: Readonly<Record<NonNullable<KernelModuleSnapshot["reason"]>, string>> = {
  budget: "Reading stopped at its request and time budget. Check again to read more.",
  "partial-history": "The network provider returned only part of the install history.",
  "unknown-context":
    "Some installs hide their permission, selector or hook scope, so not every module could be confirmed.",
};

function rootValidatorFor(signer: Readonly<OwnerCredentialProfile>): `0x${string}` | null {
  return signer.kind === "ecdsa" ? ECDSA_VALIDATOR : null;
}

function moduleLabels(signer: Readonly<OwnerCredentialProfile>, rootValidator: string) {
  const labels = new Map<string, string>([[ECDSA_VALIDATOR, "ECDSA validator"]]);
  labels.set(
    rootValidator,
    signer.kind === "ecdsa"
      ? "ECDSA validator"
      : signer.kind === "p256"
        ? "P-256 validator"
        : "WebAuthn validator",
  );
  for (const [kind, name] of [
    ["ecdsa", "OAAth ECDSA signer"],
    ["webauthn", "OAAth WebAuthn signer"],
  ] as const) {
    const address = pinnedSignerModule(kind);
    if (address) labels.set(address.toLowerCase(), name);
  }
  for (const [kind, name] of [
    ["call", "Call policy"],
    ["expiry", "Validity policy"],
    ["rate-limit", "Rate-limit policy"],
    ["operation-limit", "Operation-limit policy"],
  ] as const) {
    const address = pinnedPolicyModule(kind as never);
    if (address) labels.set(address.toLowerCase(), name);
  }
  return (module: string, moduleType: number) =>
    labels.get(module) ?? `Unknown ${MODULE_TYPES[moduleType] ?? "module"}`;
}

/** Kernel's 21-byte validation ID of an installed permission. */
function permissionValidation(permissionId: string): string {
  return `0x02${permissionId.slice(2, 10)}${"0".repeat(32)}`.toLowerCase();
}

/**
 * Attributes every module Cetane reads at one block to the root, an
 * OAAth-issued permission (`issued` permission IDs), or neither.
 */
export function attributeModules(input: {
  readonly snapshot: KernelModuleSnapshot;
  readonly account: `0x${string}`;
  readonly signer: Readonly<OwnerCredentialProfile>;
  readonly rootValidator: `0x${string}`;
  readonly issued: readonly `0x${string}`[];
}): AccountInventory {
  const { snapshot } = input;
  const root = snapshot.root?.id.toLowerCase() as `0x${string}` | undefined;
  if (!root) throw new Error("the root validation is unreadable");
  const issued = new Set(input.issued.map((id) => id.slice(0, 10).toLowerCase()));
  const label = moduleLabels(input.signer, input.rootValidator);
  const rows = new Map<string, InventoryModule>();
  const add = (
    moduleType: number,
    address: string,
    origin: ModuleOrigin,
    evidence: InventoryModule["evidence"],
  ) => {
    const module = address.toLowerCase() as `0x${string}`;
    if (module === ZERO) return;
    const key = `${moduleType}:${module}:${origin}`;
    const row = rows.get(key);
    rows.set(key, {
      moduleType,
      module,
      label: label(module, moduleType),
      origin,
      count: (row?.count ?? 0) + 1,
      evidence: row?.evidence === "history" || evidence === "history" ? "history" : "state",
    });
  };
  const rootModule = root.startsWith("0x01") ? `0x${root.slice(4)}` : null;
  // A hook's context embeds the validation it wraps.
  const hookOrigin = (context: string | undefined): ModuleOrigin => {
    const scope = context?.toLowerCase() ?? "";
    if (scope.includes(root.slice(2))) return "root";
    for (const id of issued) if (scope.includes(permissionValidation(id).slice(2))) return "oaath";
    return "outside";
  };
  for (const validator of snapshot.validators)
    add(
      1,
      validator.address,
      validator.address.toLowerCase() === rootModule ? "root" : "outside",
      "state",
    );
  for (const executor of snapshot.executors) add(2, executor.address, "outside", "state");
  for (const fallback of snapshot.fallbacks) add(3, fallback.address, "outside", "state");
  for (const hook of snapshot.hooks) add(11, hook.address, hookOrigin(hook.context), "state");
  for (const permission of snapshot.permissions) {
    const origin: ModuleOrigin =
      permission.validationId.toLowerCase() === root
        ? "root"
        : issued.has(permission.id.slice(0, 10).toLowerCase())
          ? "oaath"
          : "outside";
    add(6, permission.signer, origin, "state");
    for (const policy of permission.policies) add(5, policy, origin, "state");
  }
  // Install events no state read could confirm stay visible, as outside.
  for (const unresolved of snapshot.unresolved)
    add(Number(unresolved.type), unresolved.address, "outside", "history");

  const order: Readonly<Record<ModuleOrigin, number>> = { root: 0, outside: 1, oaath: 2 };
  const modules = [...rows.values()].sort(
    (a, b) =>
      order[a.origin] - order[b.origin] ||
      a.moduleType - b.moduleType ||
      a.module.localeCompare(b.module),
  );
  const outsideModules = modules.filter((row) => row.origin === "outside");
  const complete = snapshot.complete;
  return {
    chainId: IMPORT_CHAIN_ID,
    account: input.account,
    blockNumber: snapshot.blockNumber.toString(),
    root,
    modules,
    outside: outsideModules.reduce((sum, row) => sum + row.count, 0),
    complete,
    note: !complete && snapshot.reason ? COVERAGE_NOTES[snapshot.reason] : null,
    fingerprint: keccak256(
      toHex(
        JSON.stringify({
          chainId: IMPORT_CHAIN_ID,
          account: input.account,
          root,
          complete,
          outside: outsideModules.map((row) => [row.moduleType, row.module, row.count]),
        }),
      ),
    ),
  };
}

/**
 * Checks, in order, that `value` is a deployed reviewed Kernel v4 account whose
 * root is `signer`, then lists its modules. The first failure stops the checks.
 */
export async function inspectAccount(input: {
  readonly address: string;
  readonly signer: Readonly<OwnerCredentialProfile>;
  /** Permission IDs OAAth issued for this account; none before it is imported. */
  readonly issued?: readonly `0x${string}`[];
  /** The portal's `/rpc/421614` proxy URL. */
  readonly rpcUrl: string;
}): Promise<AccountInspection> {
  const checks: ImportCheck[] = [];
  const stop = (id: ImportCheckId, detail: string, status: "fail" | "unknown" = "fail") => {
    checks.push({ id, label: LABELS[id], status, detail });
    return { checks, compatible: false, inventory: null, inventoryError: null };
  };
  const pass = (id: ImportCheckId, detail: string) =>
    checks.push({ id, label: LABELS[id], status: "pass", detail });
  const unreadable = (id: ImportCheckId) =>
    stop(id, `${IMPORT_NETWORK} could not be read. Try again.`, "unknown");

  let account: `0x${string}`;
  try {
    account = captureAddress(input.address.trim(), "account", (message) => {
      throw new Error(message);
    });
  } catch {
    return stop("address", "Enter the account's 0x address: 40 hexadecimal characters.");
  }
  pass("address", account);

  const [ports] = createCetaneChainPorts(
    { [IMPORT_CHAIN_ID]: { publicRpcUrls: [input.rpcUrl] } },
    {
      timeoutMs: TIMEOUT_MS,
      maxRequests: CHECK_REQUESTS,
      retry: { attempts: 1 },
    },
  );
  if (!ports) return unreadable("deployed");
  const reads = ports.reads;
  const deployment = kernelDeployment({ chainId: IMPORT_CHAIN_ID });

  let code: unknown;
  try {
    code = await reads.read({ type: "code", chainId: IMPORT_CHAIN_ID, address: account });
  } catch {
    return unreadable("deployed");
  }
  if (typeof code !== "string" || code === "0x")
    return stop(
      "deployed",
      `No contract is deployed at this address on ${IMPORT_NETWORK}. Use Create account for a new account.`,
    );
  if (code.toLowerCase().startsWith("0xef0100"))
    return stop(
      "deployed",
      "This address is an EIP-7702 delegated wallet, not a Kernel v4 smart account.",
    );
  pass("deployed", `Contract deployed on ${IMPORT_NETWORK}.`);

  let implementation: string;
  try {
    implementation = String(
      await reads.read({
        type: "kernel_account_implementation",
        chainId: IMPORT_CHAIN_ID,
        account,
      }),
    ).toLowerCase();
  } catch {
    return unreadable("implementation");
  }
  if (!/^0x[0-9a-f]{40}$/u.test(implementation) || implementation === ZERO)
    return stop(
      "implementation",
      "This contract is not a Kernel smart account: it has no upgradeable implementation.",
    );
  if (implementation !== deployment.implementation)
    return stop(
      "implementation",
      `The account runs implementation ${implementation}, not the reviewed Kernel v4 (0.4.0) build OAAth supports.`,
    );
  pass("implementation", "Reviewed Kernel v4 (0.4.0) with EntryPoint 0.9.");

  const key = kernelKey({ credential: input.signer, validator: rootValidatorFor(input.signer) });
  const rootValidator = key.resolveValidator(deployment).toLowerCase() as `0x${string}`;
  let root: string;
  try {
    root = String(
      await reads.read({ type: "kernel_v4_account_root", chainId: IMPORT_CHAIN_ID, account }),
    ).toLowerCase();
  } catch {
    return unreadable("root");
  }
  if (root.startsWith("0x02"))
    return stop(
      "root",
      "The account's root is a permission, not a signer. OAAth imports accounts whose root is an ECDSA, P-256 or WebAuthn validator.",
    );
  if (root !== `0x01${rootValidator.slice(2)}`)
    return stop(
      "root",
      `The account's root validator is ${root.startsWith("0x01") ? `0x${root.slice(4)}` : "unreadable"}, not the ${moduleLabels(input.signer, rootValidator)(rootValidator, 1)} this signer uses. Sign in with the account's root signer.`,
    );
  pass("root", `${moduleLabels(input.signer, rootValidator)(rootValidator, 1)}.`);

  try {
    await createKernelRuntime({
      deployment,
      operator: ownerOperator({ key }),
      reads,
    }).bindAccount({ address: account });
  } catch (error) {
    if (
      error instanceof OaathKernelRuntimeError &&
      error.code === "kernel_runtime_binding_mismatch"
    )
      return stop(
        "owner",
        "This signer is not the account's root owner. Sign in with the signer that owns the account.",
      );
    return unreadable("owner");
  }
  pass("owner", "This signer is the account's root owner.");

  try {
    const client = createPublicClient({
      chain: { id: IMPORT_CHAIN_ID, name: IMPORT_NETWORK, nativeAA: false },
      transport: http(input.rpcUrl, {
        timeout: TIMEOUT_MS,
      }),
    });
    const snapshot = await readKernelModules(client, {
      address: account,
      version: "4",
      ...(input.issued?.length ? { permissionIds: input.issued } : {}),
      budget: INVENTORY_BUDGET,
    });
    return {
      checks,
      compatible: true,
      inventory: attributeModules({
        snapshot,
        account,
        signer: input.signer,
        rootValidator,
        issued: input.issued ?? [],
      }),
      inventoryError: null,
    };
  } catch {
    return {
      checks,
      compatible: true,
      inventory: null,
      inventoryError: `The account's installed modules could not be read from ${IMPORT_NETWORK}. Try again.`,
    };
  }
}

const IMPORT_TYPES = {
  AccountImport: [
    { name: "account", type: "address" },
    { name: "ownerProfileHash", type: "bytes32" },
    { name: "inventoryFingerprint", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "nonce", type: "string" },
  ],
} as const;

/**
 * The root's one signature that imports an account: an OAAth EIP-712
 * statement over the account, the root's own profile, the inventory it
 * acknowledged, the time and a fresh nonce. Nothing is sent on-chain.
 */
export async function signAccountImport(input: {
  readonly inventory: AccountInventory;
  readonly signer: RememberedSigner;
}): Promise<ImportAccountRequest> {
  const { inventory, signer } = input;
  // A little behind this device's clock, so a fast clock is not "in the future".
  const issuedAt = Math.floor(Date.now() / 1_000) - 5;
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const message = {
    account: inventory.account.toLowerCase() as `0x${string}`,
    ownerProfileHash: hashOwnerCredentialProfile(signer.profile),
    inventoryFingerprint: inventory.fingerprint,
    issuedAt,
    nonce,
  };
  const domain = { name: "OAAth", version: "1" } as const;
  const digest = hashTypedData({
    domain,
    types: IMPORT_TYPES,
    primaryType: "AccountImport",
    message: { ...message, issuedAt: BigInt(issuedAt) },
  });
  const key = await rootKey(signer, {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
      ],
      ...IMPORT_TYPES,
    },
    primaryType: "AccountImport",
    domain,
    message,
  });
  return {
    root_signer_id: signer.signer_id,
    address: message.account,
    inventory_fingerprint: inventory.fingerprint,
    issued_at: issuedAt,
    nonce,
    signature: await key.sign(digest),
  };
}
