/**
 * The same five chain ports, answered by a real local chain.
 *
 * `OAATH_REQUIRE_ANVIL=1` selects this file instead of ./fake-chain.mjs. Nothing
 * in ./run.mjs changes: the journey, the relay, the stores, and the credentials
 * are identical, which is the point — a chain capability is the whole boundary
 * between the SDK and a network.
 *
 * The devnet has no bundler, so the probe reports `absent` and the routing
 * decision falls back to direct `EntryPoint.handleOps` with an EOA fee payer —
 * the same prepared operation, the same hash, the same signature, a different
 * outer transaction. The observation port then rebuilds the bundler-shaped
 * receipt from the EntryPoint's own `UserOperationEvent`, which is what a
 * deployment without a bundler must do.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  encodeKernelV4InstallNonceRead,
  encodeKernelV4NonceKey,
  encodeKernelV4NonceRead,
  KERNEL_V4_ENTRY_POINT_V07,
} from "@oaath/sdk/kernel";
import { decodeEventLog, encodeFunctionData, parseEther, toEventSelector, toHex } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { deployKernelStack, startAnvil } from "../support/anvil.mjs";

const USER_OPERATION_EVENT = toEventSelector(
  "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)",
);
/** Generous fixed limits: a devnet needs no estimation to prove the journey. */
const GAS = {
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};

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

export async function createAnvilChain(chainId, { p256 = false } = {}) {
  const chain = await startAnvil(chainId, p256 ? "osaka" : "prague");
  const stack = await deployKernelStack(chain, { p256 });
  const feePayerBalance = await chain.client.getBalance({ address: stack.submitter.address });
  /** Exact operation -> submitted transaction, retained across other members' jobs. */
  const transactionHashes = new Map();
  const sends = [];

  const receiptOf = async (hash) => chain.rpc("eth_getTransactionReceipt", [hash]);

  /**
   * The receipt a bundler would have returned, rebuilt from the EntryPoint event.
   * Every field is read from the chain; the observer re-verifies all of them
   * against the transaction receipt, the transaction, and the canonical block.
   */
  const userOperationReceipt = async (userOperationHash) => {
    const transactionHash = transactionHashes.get(userOperationHash);
    if (transactionHash === undefined) return null;
    const receipt = await receiptOf(transactionHash);
    if (receipt === null) return null;
    const log = receipt.logs.find(
      (entry) =>
        entry.address === KERNEL_V4_ENTRY_POINT_V07 &&
        entry.topics[0] === USER_OPERATION_EVENT &&
        entry.topics[1] === userOperationHash,
    );
    if (log === undefined) return null;
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
  };

  async function permissionInstalled(request) {
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
  async function nonceQuote(request) {
    const nonceKey = "0";
    const key = encodeKernelV4NonceKey({
      mode: request.mode,
      validation: request.validation,
      nonceKey,
    });
    const raw = await chain.rpc("eth_call", [
      {
        to: KERNEL_V4_ENTRY_POINT_V07,
        data: encodeKernelV4NonceRead({ account: request.account, key }),
      },
      "latest",
    ]);
    if (typeof raw !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(raw))
      throw new Error("nonce_read_invalid");
    const nonce = BigInt(raw);
    if (nonce >> 64n !== BigInt(key)) throw new Error("nonce_domain_mismatch");
    return { nonceKey, sequence: (nonce & ((1n << 64n) - 1n)).toString(10), gas: GAS };
  }

  return {
    label: `local Anvil at ${chain.url} with Kernel v4`,
    validator: stack.validator,
    sends,
    fund: (account) => stack.fund(account, parseEther("1")),
    /** Pure local deployment quote. The retained approval supplies the permission identity. */
    async quoteRevocation(approval) {
      const signer = approval.packages.find((entry) => entry.moduleType === 6);
      if (!signer) throw new Error("revocation_signer_missing");
      const block = await chain.rpc("eth_getBlockByNumber", ["latest", false]);
      const code = await chain.rpc("eth_getCode", [approval.account, block.number]);
      if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code))
        throw new Error("account_code_unreadable");
      const installed =
        code === "0x"
          ? false
          : await permissionInstalled({
              account: approval.account,
              signer: signer.module,
              permissionId: signer.internalData.slice(0, 10),
              blockNumber: BigInt(block.number).toString(10),
            });
      if (installed !== true && installed !== false) throw new Error("permission_state_unreadable");
      return {
        ...(await nonceQuote({
          account: approval.account,
          mode: "standard",
          validation: { kind: "root" },
        })),
        effect: installed ? "uninstall-permission" : "invalidate-install",
      };
    },
    stop: () => chain.stop(),
    capability: {
      chainId,
      reads: stack.reads,
      observation: {
        async read(request) {
          if (request.type === "chain_id") return chainId;
          if (request.type === "user_operation_receipt") {
            return userOperationReceipt(request.userOperationHash);
          }
          if (request.type === "transaction_receipt") {
            const receipt = await receiptOf(request.transactionHash);
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
            const transaction = await chain.rpc("eth_getTransactionByHash", [
              request.transactionHash,
            ]);
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
          if (request.type === "finalized_block") {
            return blockEvidence(await chain.rpc("eth_getBlockByNumber", ["finalized", false]));
          }
          if (request.type === "canonical_block") {
            return blockEvidence(
              await chain.rpc("eth_getBlockByNumber", [toHex(BigInt(request.blockNumber)), false]),
            );
          }
          if (request.type === "block_by_hash") {
            return blockEvidence(await chain.rpc("eth_getBlockByHash", [request.blockHash, false]));
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
            return permissionInstalled(request);
          }
          throw new Error(`unsupported observation read ${request.type}`);
        },
        async close() {},
      },
      bundler: {
        async probe(request) {
          // A devnet runs no bundler. `absent` is a fact, not a failure, and it
          // is what authorizes the handleOps route below.
          return {
            accepting: false,
            chainId: request.chainId,
            supportedEntryPoints: [request.entryPoint],
          };
        },
      },
      submission: {
        async open(request) {
          sends.push(request.prepared);
          return {
            async send() {
              const sent = await stack.sendSigned(request.prepared, request.signature, (hash) => {
                // Captured before receipt waiting: an ambiguous wait cannot
                // erase the submitted transaction identity.
                transactionHashes.set(request.prepared.userOperationHash, hash);
              });
              if (sent.status !== "success") throw new Error("the handleOps transaction failed");
              // A devnet only finalizes as blocks arrive, so mine past the
              // inclusion block and let the node's own `finalized` tag catch up.
              await chain.rpc("anvil_mine", ["0x3"]);
              // The identity is unchanged by the route: the hash the bundler
              // would have returned is the hash this operation was prepared with.
              return { userOperationHash: sent.userOperationHash };
            },
            async close() {},
          };
        },
      },
      async quote(request) {
        // The quote is the first port that learns the exact account address, so
        // it is where this example prefunds it. A deployment funds accounts out
        // of band, or uses a paymaster.
        await stack.fund(request.account, parseEther("1"));
        return nonceQuote(request);
      },
      // Complete usage evidence anchored to the node's own finalized tag: the
      // finalized count is what this example actually submitted and saw
      // included. Without it, coverage is inconclusive and sendCalls is denied.
      async usage(request) {
        const block = await chain.rpc("eth_getBlockByNumber", ["finalized", false]);
        let finalizedOperationCount = 0;
        for (const prepared of sends) {
          if (prepared.kind !== "execution" || prepared.grantId !== request.grantId) continue;
          const receipt = await userOperationReceipt(prepared.userOperationHash);
          if (!receipt || BigInt(receipt.blockNumber) > BigInt(block.number)) continue;
          const canonical = await chain.rpc("eth_getBlockByNumber", [receipt.blockNumber, false]);
          if (canonical?.hash !== receipt.blockHash) throw new Error("usage_block_unreadable");
          finalizedOperationCount += 1;
        }
        return {
          version: "oaath.grant-policy-usage/v1",
          status: "complete",
          grantId: request.grantId,
          chainId: request.chainId,
          finalizedOperationCount: String(finalizedOperationCount),
          through: {
            blockNumber: BigInt(block.number).toString(10),
            blockHash: block.hash,
            observedAt: Math.floor(Date.now() / 1000),
          },
        };
      },
      feePayer: {
        address: stack.submitter.address.toLowerCase(),
        balance: feePayerBalance.toString(10),
      },
      paymasterService: null,
      staticPaymasterConfigurationHash: null,
    },
  };
}
