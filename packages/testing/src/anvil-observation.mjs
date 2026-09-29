import { encodeKernelV4InstallNonceRead, KERNEL_V4_ENTRY_POINT_V07 } from "@oaath/sdk/kernel";
import { decodeEventLog, encodeFunctionData, toEventSelector, toHex } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";

const USER_OPERATION_EVENT = toEventSelector(
  "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)",
);
/** Only the keys the observer accepts: extra fields fail its exact capture. */
const blockEvidence = (raw) =>
  raw === null
    ? null
    : {
        number: raw.number,
        hash: raw.hash,
        parentHash: raw.parentHash,
        transactions: raw.transactions,
      };
const logEvidence = (log) => ({
  address: log.address,
  blockNumber: log.blockNumber,
  blockHash: log.blockHash,
  transactionHash: log.transactionHash,
  transactionIndex: log.transactionIndex,
  logIndex: log.logIndex,
  removed: log.removed,
  topics: log.topics,
  data: log.data,
});

/** Rebuild the local receipt from chain evidence; no process-local transaction cache. */
export async function readLocalOperationReceipt(chain, userOperationHash) {
  const logs = await chain.rpc("eth_getLogs", [
    {
      address: KERNEL_V4_ENTRY_POINT_V07,
      fromBlock: "0x0",
      toBlock: "latest",
      topics: [USER_OPERATION_EVENT, userOperationHash],
    },
  ]);
  if (!Array.isArray(logs)) throw new Error("local_receipt_unreadable");
  if (logs.length === 0) return null;
  if (logs.length !== 1 || logs[0].removed !== false) throw new Error("local_receipt_ambiguous");
  const receipt = await chain.rpc("eth_getTransactionReceipt", [logs[0].transactionHash]);
  if (receipt === null) return null;
  const log = receipt.logs.find(
    (entry) =>
      entry.address === KERNEL_V4_ENTRY_POINT_V07 &&
      entry.topics[0] === USER_OPERATION_EVENT &&
      entry.topics[1] === userOperationHash,
  );
  if (!log) return null;
  const { args } = decodeEventLog({ abi: entryPoint07Abi, data: log.data, topics: log.topics });
  return {
    userOperationHash,
    entryPoint: KERNEL_V4_ENTRY_POINT_V07,
    sender: `0x${log.topics[2].slice(26)}`,
    nonce: toHex(args.nonce),
    paymaster: `0x${log.topics[3].slice(26)}`,
    actualGasCost: toHex(args.actualGasCost),
    actualGasUsed: toHex(args.actualGasUsed),
    success: args.success,
    transactionHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
  };
}
export async function readLocalPermissionInstalled(chain, request) {
  // Kernel's own isModuleInstalled(6, signer, permissionId) at the
  // anchored block: true exactly while the permission validation is
  // live. Anything but a well-formed boolean is no answer.
  const data = encodeFunctionData({
    abi: [
      {
        type: "function",
        name: "isModuleInstalled",
        stateMutability: "view",
        inputs: [{ type: "uint256" }, { type: "address" }, { type: "bytes" }],
        outputs: [{ type: "bool" }],
      },
    ],
    functionName: "isModuleInstalled",
    args: [6n, request.signer, request.permissionId],
  });
  const answer = await chain.rpc("eth_call", [
    { to: request.account, data },
    `0x${BigInt(request.blockNumber).toString(16)}`,
  ]);
  if (answer === `0x${"0".repeat(64)}`) return false;
  if (answer === `0x${"0".repeat(63)}1`) return true;
  return null;
}

export function createLocalAnvilObservation(chain) {
  return {
    async read(request) {
      if (request.type === "chain_id") return chain.chainId;
      if (request.type === "user_operation_receipt") {
        return readLocalOperationReceipt(chain, request.userOperationHash);
      }
      if (request.type === "transaction_receipt") {
        const receipt = await chain.rpc("eth_getTransactionReceipt", [request.transactionHash]);
        return receipt === null
          ? null
          : {
              transactionHash: receipt.transactionHash,
              blockNumber: receipt.blockNumber,
              blockHash: receipt.blockHash,
              transactionIndex: receipt.transactionIndex,
              status: receipt.status,
              gasUsed: receipt.gasUsed,
              logs: receipt.logs.map(logEvidence),
            };
      }
      if (request.type === "transaction") {
        const transaction = await chain.rpc("eth_getTransactionByHash", [request.transactionHash]);
        return transaction === null
          ? null
          : {
              hash: transaction.hash,
              to: transaction.to,
              blockNumber: transaction.blockNumber,
              blockHash: transaction.blockHash,
              transactionIndex: transaction.transactionIndex,
            };
      }
      if (request.type === "transaction_execution") {
        const transaction = await chain.rpc("eth_getTransactionByHash", [request.transactionHash]);
        return transaction === null
          ? null
          : {
              hash: transaction.hash,
              to: transaction.to,
              blockNumber: transaction.blockNumber,
              blockHash: transaction.blockHash,
              input: transaction.input,
            };
      }
      if (request.type === "finalized_block") {
        return blockEvidence(await chain.rpc("eth_getBlockByNumber", ["finalized", false]));
      }
      if (request.type === "canonical_block") {
        return blockEvidence(
          await chain.rpc("eth_getBlockByNumber", [toHex(BigInt(request.blockNumber)), false]),
        );
      }
      // A replacement search needs an indexer; this example submits one
      // operation per lane and never claims to have looked.
      if (request.type === "replacement_candidate") return null;
      if (request.type === "entry_point_nonce") {
        // The node's own EntryPoint.getNonce for the operation's 192-bit
        // key, read at the anchored block the observer names.
        const data = encodeFunctionData({
          abi: entryPoint07Abi,
          functionName: "getNonce",
          args: [request.account, BigInt(request.nonce) >> 64n],
        });
        return await chain.rpc("eth_call", [
          { to: request.entryPoint, data },
          `0x${BigInt(request.blockNumber).toString(16)}`,
        ]);
      }
      if (request.type === "kernel_install_nonce") {
        return await chain.rpc("eth_call", [
          {
            to: request.account,
            data: encodeKernelV4InstallNonceRead({
              key: (BigInt(request.nonce) >> 64n).toString(10),
            }),
          },
          `0x${BigInt(request.blockNumber).toString(16)}`,
        ]);
      }
      if (request.type === "kernel_permission_installed") {
        return readLocalPermissionInstalled(chain, request);
      }
      throw new Error(`unsupported observation read ${request.type}`);
    },
    async close() {},
  };
}
