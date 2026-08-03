import { constants, KernelV3_1AccountAbi } from "@zerodev/sdk";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import {
  concatHex,
  encodeFunctionData,
  getContractAddress,
  keccak256,
  pad,
  toHex,
  zeroAddress,
} from "viem";
import { KERNEL_RUNTIME_CAPABILITIES } from "../kernel-runtime-capabilities.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const MAX_UINT256 = (1n << 256n) - 1n;

export interface KernelV3_3RootIdentity {
  readonly validatorAddress: `0x${string}`;
  readonly enableData: `0x${string}`;
  readonly accountIndex: string;
}

export type KernelV3_3AccountDerivationFailure = (message: string) => never;

function lowerAddress(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

/**
 * Owns the exact Kernel 0.3.3 root-validator CREATE2 identity shared by custom
 * validator adapters. It is pure and introduces no chain-support decision.
 */
export function deriveKernelV3_3AccountAddress(
  identity: Readonly<KernelV3_3RootIdentity>,
  fail: KernelV3_3AccountDerivationFailure,
): `0x${string}` {
  if (
    !ADDRESS.test(identity.validatorAddress) ||
    !BYTES.test(identity.enableData) ||
    !DECIMAL_UINT.test(identity.accountIndex) ||
    BigInt(identity.accountIndex) > MAX_UINT256
  ) {
    return fail("Kernel 0.3.3 root identity is invalid");
  }

  const sdk = constants.KernelVersionToAddressesMap[KERNEL_V3_3];
  const manifest = KERNEL_RUNTIME_CAPABILITIES.contracts.kernel;
  if (
    typeof sdk.metaFactoryAddress !== "string" ||
    lowerAddress(sdk.accountImplementationAddress) !== lowerAddress(manifest.implementation) ||
    lowerAddress(sdk.factoryAddress) !== lowerAddress(manifest.factory) ||
    lowerAddress(sdk.metaFactoryAddress) !== lowerAddress(manifest.metaFactory) ||
    typeof sdk.initCodeHash !== "string" ||
    !HASH.test(sdk.initCodeHash)
  ) {
    return fail("Kernel 0.3.3 deployment does not match the pinned runtime");
  }

  const initializationData = encodeFunctionData({
    abi: KernelV3_1AccountAbi,
    functionName: "initialize",
    args: [
      pad(concatHex(["0x01", identity.validatorAddress]), { size: 21, dir: "right" }),
      zeroAddress,
      identity.enableData,
      "0x",
      [],
    ],
  });
  return lowerAddress(
    getContractAddress({
      bytecodeHash: sdk.initCodeHash as `0x${string}`,
      from: sdk.factoryAddress,
      opcode: "CREATE2",
      salt: keccak256(
        concatHex([initializationData, toHex(BigInt(identity.accountIndex), { size: 32 })]),
      ),
    }),
  );
}
