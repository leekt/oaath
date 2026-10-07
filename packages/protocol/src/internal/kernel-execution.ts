import type { Hex } from "cetane";
import { concatHex, encodeAbiParameters, encodeFunctionData, parseAbi, toHex } from "cetane/utils";

const ABI = parseAbi(["function execute(bytes32 mode, bytes executionData) payable"]);
const BATCH = [
  {
    type: "tuple[]",
    components: [
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
  },
] as const;

/**
 * Kernel 0.4.0's ERC-7579 `execute` calldata for captured calls: the single
 * call type for one call, the batch call type otherwise, default exec type.
 */
export function encodeKernelExecution(
  calls: readonly Readonly<{ target: Hex; value: string; data: Hex }>[],
): Hex {
  const single = calls.length === 1 ? calls[0] : undefined;
  const executionData = single
    ? concatHex([single.target, toHex(BigInt(single.value), { size: 32 }), single.data])
    : encodeAbiParameters(BATCH, [
        calls.map((call) => ({ to: call.target, value: BigInt(call.value), data: call.data })),
      ]);
  return encodeFunctionData({
    abi: ABI,
    functionName: "execute",
    args: [single ? `0x${"00".repeat(32)}` : `0x01${"00".repeat(31)}`, executionData],
  });
}
