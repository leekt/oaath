/**
 * Closed Kernel v4 revocation calls and owner-phone signing wire.
 * No submission, authority decision, chain observation, or finality lives here.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  concat,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  keccak256,
  parseAbi,
  toHex,
} from "viem";
import {
  getUserOperationHash,
  toUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import { hashOwnerCredentialProfile } from "./identity-profile.js";
import { exactRecord } from "./internal/exact-record.js";
import {
  type KernelV4Install,
  type KernelV4ReplayableInstallOwnerSigningRequest,
  parseKernelV4InstallPackages,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
} from "./kernel-v4-replayable-install.js";
import {
  hashPermissionRequest,
  type PermissionRequest,
  parsePermissionRequest,
} from "./permission-protocol.js";
import { hashOwnerSigningRequest } from "./signing-request.js";

export const OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION =
  "oaath.kernel-revocation-signing-request/v1" as const;
const ERROR_CODE = "signing_request_invalid" as const;
const fail = protocolFailure(ERROR_CODE);
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_UINT120 = (1n << 120n) - 1n;
const ABI = parseAbi([
  "function setNonce(uint192 nonceKey, uint64 seq)",
  "function uninstallModule(uint256 moduleType, address module, bytes initData) payable",
  "function execute(bytes32 mode, bytes executionData) payable",
]);
const MODULE_DATA = [
  { name: "installData", type: "bytes" },
  { name: "internalData", type: "bytes" },
] as const;

export type KernelV4RevocationEffect = "invalidate-install" | "uninstall-permission";
type Call = Readonly<{ target: Hex; value: string; data: Hex }>;

/** EntryPoint 0.7's packed unsigned operation, with decimal integers for JSON. */
export interface KernelV4RevocationOperation {
  readonly sender: Hex;
  readonly nonce: string;
  readonly initCode: Hex;
  readonly callData: Hex;
  readonly accountGasLimits: Hex;
  readonly preVerificationGas: string;
  readonly gasFees: Hex;
  /** This first owner-phone revocation profile is self-funded. */
  readonly paymasterAndData: "0x";
}

export interface KernelV4RevocationSigningRequest {
  readonly version: typeof OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION;
  readonly kind: "kernel-revocation";
  readonly permissionRequest: Readonly<PermissionRequest>;
  /** Public install scope only; no retained enable signature is sent to the phone. */
  readonly install: Readonly<KernelV4ReplayableInstallOwnerSigningRequest>;
  readonly effect: KernelV4RevocationEffect;
  readonly chainId: number;
  /** EntryPoint 0.7 address, part of the digest the phone independently derives. */
  readonly entryPoint: Hex;
  readonly operation: Readonly<KernelV4RevocationOperation>;
  readonly expectedDigest: Hex;
}

function address(value: unknown, label: string): Hex {
  if (
    typeof value !== "string" ||
    !/^0x[0-9a-f]{40}$/u.test(value) ||
    value === `0x${"00".repeat(20)}`
  )
    return fail(`${label} is invalid`);
  return value as Hex;
}

function bytes(value: unknown, label: string, size?: number): Hex {
  if (
    typeof value !== "string" ||
    !/^0x(?:[0-9a-f]{2})*$/u.test(value) ||
    value.length > 131_074 ||
    (size !== undefined && value.length !== 2 + size * 2)
  )
    return fail(`${label} is invalid`);
  return value as Hex;
}

function uint(value: unknown, maximum: bigint, label: string): bigint {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]{0,77})$/u.test(value) ||
    BigInt(value) > maximum
  )
    return fail(`${label} is invalid`);
  return BigInt(value);
}

/**
 * Removes policies in reverse install order, then their signer. Kernel requires
 * that order; the install packages own the permission identity and module data.
 */
export function encodeKernelV4PermissionUninstallCalls(value: {
  readonly account: Hex;
  readonly packages: readonly KernelV4Install[];
}): readonly Call[] {
  return capturedByProtocol(ERROR_CODE, "Kernel permission uninstall is invalid", () => {
    const record = exactRecord(
      value,
      ["account", "packages"],
      "Kernel permission uninstall",
      new WeakSet(),
      fail,
    );
    const account = address(record.account, "Kernel permission uninstall account");
    const packages = parseKernelV4InstallPackages(record.packages);
    const policies = packages.filter((entry) => entry.moduleType === 5);
    const signers = packages.filter((entry) => entry.moduleType === 6);
    if (signers.length !== 1 || policies.length + 1 !== packages.length)
      return fail("Kernel permission uninstall requires policy packages and exactly one signer");
    if (packages.some((entry) => entry.moduleData.length < 66))
      return fail("Kernel permission uninstall packages must carry the permission prefix");
    return Object.freeze(
      [...policies.reverse(), ...signers].map((entry) =>
        Object.freeze({
          target: account,
          value: "0",
          data: encodeFunctionData({
            abi: ABI,
            functionName: "uninstallModule",
            args: [
              BigInt(entry.moduleType),
              entry.module,
              encodeAbiParameters(MODULE_DATA, [
                entry.moduleData.slice(0, 66) as Hex,
                entry.internalData,
              ]),
            ],
          }),
        }),
      ),
    );
  });
}

/**
 * An owner self-call that invalidates an unused install approval on one chain.
 * Already consumed/invalidated approvals require observation: setNonce must
 * increase the stored sequence. Installed permissions still need uninstall.
 */
export function encodeKernelV4InstallNonceInvalidationCall(value: {
  readonly account: Hex;
  readonly installNonce: string;
}): Call {
  return capturedByProtocol(ERROR_CODE, "Kernel install nonce invalidation is invalid", () => {
    const record = exactRecord(
      value,
      ["account", "installNonce"],
      "Kernel install nonce invalidation",
      new WeakSet(),
      fail,
    );
    const account = address(record.account, "Kernel install nonce account");
    const nonce = uint(record.installNonce, MAX_UINT256, "Kernel install nonce");
    const sequence = nonce & MAX_UINT64;
    if (sequence === MAX_UINT64) return fail("Kernel install nonce sequence is exhausted");
    return Object.freeze({
      target: account,
      value: "0",
      data: encodeFunctionData({
        abi: ABI,
        functionName: "setNonce",
        args: [nonce >> 64n, sequence + 1n],
      }),
    });
  });
}

function revocationCallData(
  install: KernelV4ReplayableInstallOwnerSigningRequest,
  effect: KernelV4RevocationEffect,
): Hex {
  const account = install.signer.account;
  const calls =
    effect === "invalidate-install"
      ? [
          encodeKernelV4InstallNonceInvalidationCall({
            account,
            installNonce: install.replay.nonce,
          }),
        ]
      : encodeKernelV4PermissionUninstallCalls({
          account,
          packages: install.typedData.message.packages.map((entry) => ({
            ...entry,
            moduleType: Number(entry.moduleType) as KernelV4Install["moduleType"],
          })),
        });
  const single = calls.length === 1 ? calls[0] : undefined;
  const executionData = single
    ? concat([single.target, toHex(0n, { size: 32 }), single.data])
    : encodeAbiParameters(
        [
          {
            type: "tuple[]",
            components: [
              { name: "to", type: "address" },
              { name: "value", type: "uint256" },
              { name: "data", type: "bytes" },
            ],
          },
        ],
        [calls.map((call) => ({ to: call.target, value: 0n, data: call.data }))],
      );
  return encodeFunctionData({
    abi: ABI,
    functionName: "execute",
    args: [single ? `0x${"00".repeat(32)}` : `0x01${"00".repeat(31)}`, executionData],
  });
}

/**
 * Captures one closed, self-funded Kernel 0.4.0 / EntryPoint 0.7 revocation.
 * Checks call meaning and digest. The owner device still binds its paired
 * account/key, current review and configured chain before releasing a signature.
 */
export function parseKernelV4RevocationSigningRequest(
  value: unknown,
): Readonly<KernelV4RevocationSigningRequest> {
  return capturedByProtocol(ERROR_CODE, "Kernel revocation request is invalid", () => {
    const context = new WeakSet();
    const record = exactRecord(
      value,
      [
        "version",
        "kind",
        "permissionRequest",
        "install",
        "effect",
        "chainId",
        "entryPoint",
        "operation",
        "expectedDigest",
      ],
      "Kernel revocation request",
      context,
      fail,
    );
    if (
      record.version !== OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION ||
      record.kind !== "kernel-revocation"
    )
      return fail("Kernel revocation version or kind is unsupported");
    if (record.effect !== "invalidate-install" && record.effect !== "uninstall-permission")
      return fail("Kernel revocation effect is unsupported");
    if (
      typeof record.chainId !== "number" ||
      !Number.isSafeInteger(record.chainId) ||
      record.chainId < 1
    )
      return fail("Kernel revocation chain is invalid");
    const permissionRequest = parsePermissionRequest(record.permissionRequest);
    const install = parseKernelV4ReplayableInstallOwnerSigningRequest(record.install);
    if (
      install.signer.ownerCredential.kind !== "p256" ||
      hashOwnerCredentialProfile(install.signer.ownerCredential) !==
        hashOwnerCredentialProfile(permissionRequest.logicalAccount.ownerCredential)
    )
      return fail("Kernel revocation owner contradicts the permission request");
    const op = exactRecord(
      record.operation,
      [
        "sender",
        "nonce",
        "initCode",
        "callData",
        "accountGasLimits",
        "preVerificationGas",
        "gasFees",
        "paymasterAndData",
      ],
      "Kernel revocation operation",
      context,
      fail,
    );
    if (op.paymasterAndData !== "0x") return fail("Kernel phone revocation must be self-funded");
    const operation: Readonly<KernelV4RevocationOperation> = Object.freeze({
      sender: address(op.sender, "Kernel revocation sender"),
      nonce: uint(op.nonce, MAX_UINT256, "Kernel revocation operation nonce").toString(10),
      initCode: bytes(op.initCode, "Kernel revocation initCode"),
      callData: bytes(op.callData, "Kernel revocation calldata"),
      accountGasLimits: bytes(op.accountGasLimits, "Kernel revocation gas limits", 32),
      preVerificationGas: uint(
        op.preVerificationGas,
        MAX_UINT120,
        "Kernel revocation preVerificationGas",
      ).toString(10),
      gasFees: bytes(op.gasFees, "Kernel revocation gas fees", 32),
      paymasterAndData: "0x",
    });
    // Only standard root validation, with the existing uint16 operation namespace.
    if (BigInt(operation.nonce) >> 80n !== 0n || operation.sender !== install.signer.account)
      return fail("Kernel revocation must use the bound root account");
    if (
      operation.initCode !== "0x" &&
      (operation.initCode.length < 42 || operation.initCode.startsWith(`0x7702${"00".repeat(18)}`))
    )
      return fail("Kernel revocation factory data is unsupported");
    if (operation.callData !== revocationCallData(install, record.effect))
      return fail("Kernel revocation contains calls outside its effect");
    const entryPoint = address(record.entryPoint, "Kernel revocation EntryPoint");
    const expectedDigest = bytes(record.expectedDigest, "Kernel revocation digest", 32);
    // viem delegates packed conversion to ox; its current declaration retains
    // the input shape although the implementation returns the unpacked fields.
    const userOperation = toUserOperation({
      ...operation,
      nonce: BigInt(operation.nonce),
      preVerificationGas: BigInt(operation.preVerificationGas),
      signature: "0x",
    }) as unknown as UserOperation<"0.7">;
    if (
      expectedDigest !==
      getUserOperationHash({
        chainId: record.chainId,
        entryPointAddress: entryPoint,
        entryPointVersion: "0.7",
        userOperation,
      })
    )
      return fail("Kernel revocation digest contradicts its operation");
    return Object.freeze({
      version: OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION,
      kind: "kernel-revocation",
      permissionRequest,
      install,
      effect: record.effect,
      chainId: record.chainId,
      entryPoint,
      operation,
      expectedDigest,
    });
  });
}

/**
 * Hashes a captured request for the returned artifact. Parse wire/storage input
 * once with parseKernelV4RevocationSigningRequest before calling this pure hash.
 */
export function hashKernelV4RevocationSigningRequest(
  request: Readonly<KernelV4RevocationSigningRequest>,
): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "string" },
        { type: "bytes32" },
      ],
      [
        OAATH_KERNEL_V4_REVOCATION_SIGNING_REQUEST_VERSION,
        hashPermissionRequest(request.permissionRequest),
        hashOwnerSigningRequest(request.install),
        request.effect,
        request.expectedDigest,
      ],
    ),
  );
}
