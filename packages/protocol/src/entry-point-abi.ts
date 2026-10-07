import { parseAbi } from "cetane/utils";

/** Shared packed-operation wire ABI used by EntryPoint 0.7 and 0.9. */
export const entryPointAbi = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "struct UserOpsPerAggregator { PackedUserOperation[] userOps; address aggregator; bytes signature; }",
  "function handleOps(PackedUserOperation[] ops, address beneficiary)",
  "function handleAggregatedOps(UserOpsPerAggregator[] opsPerAggregator, address beneficiary)",
  "function getNonce(address sender, uint192 key) view returns (uint256 nonce)",
  "function getUserOpHash(PackedUserOperation userOp) view returns (bytes32)",
  "function getSenderAddress(bytes initCode)",
  "function balanceOf(address account) view returns (uint256)",
  "function depositTo(address account) payable",
  "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)",
  "error FailedOp(uint256 opIndex, string reason)",
  "error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)",
  "error SenderAddressResult(address sender)",
]);
