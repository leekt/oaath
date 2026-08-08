/**
 * Exact Kernel v4 replayable-install signing profile.
 *
 * This module is the single owner of the chainless EIP-712 value that Kernel
 * 0.4.0 verifies for an enable-replayable install. It also refines a generic
 * owner-signing request only after every profile binding agrees. It does not
 * authorize a request or verify a returned signature.
 *
 * @author taek <leekt216@gmail.com>
 */

import { getAddress } from "viem";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureDenseArray,
  exactRecord,
} from "./internal/exact-record.js";
import {
  type CanonicalEip712Object,
  type CanonicalEip712TypedData,
  type Eip712OwnerSigningRequest,
  hashCanonicalEip712TypedData,
  parseCanonicalEip712TypedData,
  parseOwnerSigningRequest,
} from "./signing-request.js";

const ERROR_CODE = "signing_request_invalid" as const;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]*)$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_PACKAGES = 256;

export const KERNEL_V4_INSTALL_COMPONENTS = Object.freeze([
  Object.freeze({ name: "moduleType", type: "uint256" }),
  Object.freeze({ name: "module", type: "address" }),
  Object.freeze({ name: "moduleData", type: "bytes" }),
  Object.freeze({ name: "internalData", type: "bytes" }),
] as const);

export type KernelV4ModuleType = 1 | 2 | 3 | 4 | 5 | 6;

export interface KernelV4Install {
  readonly moduleType: KernelV4ModuleType;
  readonly module: `0x${string}`;
  readonly moduleData: `0x${string}`;
  readonly internalData: `0x${string}`;
}

const KERNEL_V4_REPLAYABLE_INSTALL_TYPES = Object.freeze({
  EIP712Domain: Object.freeze([
    Object.freeze({ name: "name", type: "string" }),
    Object.freeze({ name: "version", type: "string" }),
    Object.freeze({ name: "verifyingContract", type: "address" }),
  ] as const),
  InstallPackages: Object.freeze([
    Object.freeze({ name: "nonce", type: "uint256" }),
    Object.freeze({ name: "packages", type: "Install[]" }),
  ] as const),
  Install: KERNEL_V4_INSTALL_COMPONENTS,
});

export interface KernelV4ReplayableInstallPackage extends CanonicalEip712Object {
  readonly moduleType: string;
  readonly module: `0x${string}`;
  readonly moduleData: `0x${string}`;
  readonly internalData: `0x${string}`;
}

export interface KernelV4ReplayableInstallTypedData extends CanonicalEip712TypedData {
  readonly types: Readonly<{
    readonly EIP712Domain: readonly [
      Readonly<{ readonly name: "name"; readonly type: "string" }>,
      Readonly<{ readonly name: "version"; readonly type: "string" }>,
      Readonly<{ readonly name: "verifyingContract"; readonly type: "address" }>,
    ];
    readonly InstallPackages: readonly [
      Readonly<{ readonly name: "nonce"; readonly type: "uint256" }>,
      Readonly<{ readonly name: "packages"; readonly type: "Install[]" }>,
    ];
    readonly Install: typeof KERNEL_V4_INSTALL_COMPONENTS;
  }>;
  readonly primaryType: "InstallPackages";
  readonly domain: Readonly<
    CanonicalEip712Object & {
      readonly name: "Kernel";
      readonly version: "0.4.0";
      readonly verifyingContract: `0x${string}`;
    }
  >;
  readonly message: Readonly<
    CanonicalEip712Object & {
      readonly nonce: string;
      readonly packages: readonly Readonly<KernelV4ReplayableInstallPackage>[];
    }
  >;
}

export interface KernelV4ReplayableInstallTypedDataInput {
  readonly account: `0x${string}`;
  readonly nonce: string;
  readonly packages: readonly Readonly<KernelV4Install>[];
}

export interface KernelV4ReplayableInstallOwnerSigningRequest extends Eip712OwnerSigningRequest {
  readonly purpose: "kernel-enable";
  readonly typedData: Readonly<KernelV4ReplayableInstallTypedData>;
  readonly replay: Readonly<{ readonly nonce: string; readonly deadline: null }>;
}

function address(value: unknown, label: string, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string") return fail(`${label} must be a nonzero address`);
  try {
    const canonical = getAddress(value).toLowerCase() as `0x${string}`;
    if (!ADDRESS.test(canonical) || canonical === ZERO_ADDRESS) {
      return fail(`${label} must be a nonzero address`);
    }
    return canonical;
  } catch {
    return fail(`${label} must be a nonzero address`);
  }
}

function decimalUint(value: unknown, label: string, fail: CaptureFailure): string {
  if (
    typeof value !== "string" ||
    !DECIMAL_UINT.test(value) ||
    value.length > 78 ||
    BigInt(value) > MAX_UINT256
  ) {
    return fail(`${label} must be a canonical decimal uint256 string`);
  }
  return value;
}

function bytes(value: unknown, label: string, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !BYTES.test(value)) {
    return fail(`${label} must be canonical lowercase even-length hex`);
  }
  return value as `0x${string}`;
}

function captureInstall(
  value: unknown,
  index: number,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<KernelV4Install> {
  const record = exactRecord(
    value,
    ["moduleType", "module", "moduleData", "internalData"],
    `Kernel enable install ${index}`,
    context,
    fail,
  );
  if (
    typeof record.moduleType !== "number" ||
    !Number.isSafeInteger(record.moduleType) ||
    record.moduleType < 1 ||
    record.moduleType > 6
  ) {
    return fail("Kernel enable module type is unsupported");
  }
  return Object.freeze({
    moduleType: record.moduleType as KernelV4ModuleType,
    module: address(record.module, "Kernel enable module", fail),
    moduleData: bytes(record.moduleData, "Kernel enable module data", fail),
    internalData: bytes(record.internalData, "Kernel enable internal data", fail),
  });
}

function captureInstallPackages(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): readonly Readonly<KernelV4Install>[] {
  const entries = captureDenseArray(value, "Kernel enable packages", context, fail);
  if (entries.length < 1 || entries.length > MAX_PACKAGES) {
    return fail("Kernel enable package count is invalid");
  }
  const packages = Object.freeze(
    entries.map((entry, index) => captureInstall(entry, index, context, fail)),
  );
  let pendingPermission: string | undefined;
  for (const pkg of packages) {
    if (pkg.moduleType !== 5 && pkg.moduleType !== 6) continue;
    if (pkg.internalData.length < 10) return fail("Kernel permission package is invalid");
    const permission = pkg.internalData.slice(0, 10);
    if (pendingPermission && pendingPermission !== permission) {
      return fail("Kernel permission package sequence is invalid");
    }
    if (pkg.moduleType === 6 && !pendingPermission) {
      return fail("Kernel permission package sequence is invalid");
    }
    pendingPermission = pkg.moduleType === 5 ? permission : undefined;
  }
  if (pendingPermission) return fail("Kernel permission package sequence is incomplete");
  return packages;
}

/** Captures the one current Kernel v4 install-package representation. */
export function parseKernelV4InstallPackages(value: unknown): readonly Readonly<KernelV4Install>[] {
  return capturedByProtocol(
    ERROR_CODE,
    "Kernel v4 install packages could not be captured safely",
    () => captureInstallPackages(value, new WeakSet(), protocolFailure(ERROR_CODE)),
  );
}

function captureInput(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<KernelV4ReplayableInstallTypedDataInput> {
  const record = exactRecord(
    value,
    ["account", "nonce", "packages"],
    "Kernel enable typed-data input",
    context,
    fail,
  );
  return Object.freeze({
    account: address(record.account, "Kernel enable account", fail),
    nonce: decimalUint(record.nonce, "Kernel enable nonce", fail),
    packages: captureInstallPackages(record.packages, context, fail),
  });
}

function createCapturedTypedData(
  input: Readonly<KernelV4ReplayableInstallTypedDataInput>,
): Readonly<KernelV4ReplayableInstallTypedData> {
  return Object.freeze({
    types: KERNEL_V4_REPLAYABLE_INSTALL_TYPES,
    primaryType: "InstallPackages",
    domain: Object.freeze({
      name: "Kernel",
      version: "0.4.0",
      verifyingContract: input.account,
    }),
    message: Object.freeze({
      nonce: input.nonce,
      packages: Object.freeze(
        input.packages.map((install) =>
          Object.freeze({
            moduleType: install.moduleType.toString(10),
            module: install.module,
            moduleData: install.moduleData,
            internalData: install.internalData,
          }),
        ),
      ),
    }),
  });
}

/** Builds the exact chainless EIP-712 value Kernel 0.4.0 verifies. */
export function createKernelV4ReplayableInstallTypedData(
  value: KernelV4ReplayableInstallTypedDataInput,
): Readonly<KernelV4ReplayableInstallTypedData> {
  return capturedByProtocol(
    ERROR_CODE,
    "Kernel enable typed data could not be captured safely",
    () => {
      const typedData = createCapturedTypedData(
        captureInput(value, new WeakSet(), protocolFailure(ERROR_CODE)),
      );
      parseCanonicalEip712TypedData(typedData);
      return typedData;
    },
  );
}

function sameValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  const leftArray = Array.isArray(left);
  if (leftArray !== Array.isArray(right)) return false;
  if (leftArray) {
    const leftEntries = left as readonly unknown[];
    const rightEntries = right as readonly unknown[];
    return (
      leftEntries.length === rightEntries.length &&
      leftEntries.every((entry, index) => sameValue(entry, rightEntries[index]))
    );
  }
  const leftRecord = left as Readonly<Record<string, unknown>>;
  const rightRecord = right as Readonly<Record<string, unknown>>;
  const leftKeys = Object.keys(leftRecord);
  const rightKeys = Object.keys(rightRecord);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key) => Object.hasOwn(rightRecord, key) && sameValue(leftRecord[key], rightRecord[key]),
    )
  );
}

/**
 * Captures and refines only an exact Kernel enable request whose signer,
 * typed-data digest, and replay facts all describe the same install.
 */
export function parseKernelV4ReplayableInstallOwnerSigningRequest(
  value: unknown,
): Readonly<KernelV4ReplayableInstallOwnerSigningRequest> {
  return capturedByProtocol(
    ERROR_CODE,
    "Kernel enable owner signing request could not be captured safely",
    () => {
      const fail = protocolFailure(ERROR_CODE);
      const request = parseOwnerSigningRequest(value);
      if (
        request.kind !== "eip712" ||
        request.purpose !== "kernel-enable" ||
        request.replay.nonce === null ||
        request.replay.deadline !== null
      ) {
        return fail("owner signing request is not an exact Kernel enable request");
      }
      const packageValues = request.typedData.message.packages;
      if (!Array.isArray(packageValues)) {
        return fail("Kernel enable typed data does not contain install packages");
      }
      const expectedTypedData = createKernelV4ReplayableInstallTypedData({
        account: request.signer.account,
        nonce: request.replay.nonce,
        packages: packageValues.map((entry) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
            return fail("Kernel enable typed data contains an invalid install package");
          }
          const record = entry as Readonly<Record<string, unknown>>;
          return {
            moduleType: Number(record.moduleType) as KernelV4ModuleType,
            module: record.module as `0x${string}`,
            moduleData: record.moduleData as `0x${string}`,
            internalData: record.internalData as `0x${string}`,
          };
        }),
      });
      if (!sameValue(request.typedData, expectedTypedData)) {
        return fail("Kernel enable typed data contradicts its signing profile");
      }
      if (request.expectedDigest !== hashCanonicalEip712TypedData(request.typedData)) {
        return fail("Kernel enable expected digest does not match its typed data");
      }
      return request as Readonly<KernelV4ReplayableInstallOwnerSigningRequest>;
    },
  );
}
