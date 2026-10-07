/**
 * Closed Kernel v4 revocation calls.
 * No submission, authority decision, chain observation, or finality lives here.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { Hex } from "cetane";
import { encodeAbiParameters, encodeFunctionData, parseAbi } from "cetane/utils";
import { captureAddress } from "./address.js";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import { exactRecord } from "./internal/exact-record.js";
import { type KernelInstall, parseKernelInstallPackages } from "./kernel-v4-replayable-install.js";

const ERROR_CODE = "signing_request_invalid" as const;
const fail = protocolFailure(ERROR_CODE);
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;
const ABI = parseAbi([
  "function setNonce(uint192 nonceKey, uint64 seq)",
  "function uninstallModule(uint256 moduleType, address module, bytes initData) payable",
]);
const MODULE_DATA = [
  { name: "installData", type: "bytes" },
  { name: "internalData", type: "bytes" },
] as const;

type Call = Readonly<{ target: Hex; value: string; data: Hex }>;

function address(value: unknown, label: string): Hex {
  return captureAddress(value, label, fail);
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
export function encodeKernelPermissionUninstallCalls(value: {
  readonly account: Hex;
  readonly packages: readonly KernelInstall[];
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
    const packages = parseKernelInstallPackages(record.packages);
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
export function encodeKernelInstallNonceInvalidationCall(value: {
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
