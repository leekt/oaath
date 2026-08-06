/**
 * The default chain for the browser example: injected facts, no network.
 *
 * A chain capability is a plain object of ports — account reads, a bundler probe,
 * a submission transport, a fee quote, and observation evidence. The SDK never
 * reaches past it, so injecting these five is enough to run the whole journey on
 * a laptop with nothing installed. `OAATH_REQUIRE_ANVIL=1` swaps this file for
 * ./anvil-chain.mjs, which answers the identical ports from a real chain.
 *
 * What stays honest here: the submission transport records exactly the snapshot
 * it was handed and the observation evidence is derived from that snapshot, so
 * the operation identity the example finalizes is the one it submitted.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  kernelV4Deployment,
} from "@oaath/sdk/kernel";

const ACCOUNT = `0x${"66".repeat(20)}`;
const TRANSACTION_HASH = `0x${"44".repeat(32)}`;
const BLOCK_HASH = `0x${"55".repeat(32)}`;
const PARENT_HASH = `0x${"aa".repeat(32)}`;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const USER_OPERATION_EVENT = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const INCLUSION_BLOCK = 20n;

const quantity = (value) => `0x${value.toString(16)}`;
const word = (value) => value.toString(16).padStart(64, "0");

/** The validator address the example's key profiles are configured with. */
const VALIDATOR = `0x${"22".repeat(20)}`;

export function createFakeChain(chainId) {
  const deployment = kernelV4Deployment(chainId);
  /** Every snapshot the transport was handed, newest last. */
  const sends = [];
  const inclusionBlock = {
    number: quantity(INCLUSION_BLOCK),
    hash: BLOCK_HASH,
    parentHash: PARENT_HASH,
    transactions: [TRANSACTION_HASH],
  };

  const submitted = () => sends[sends.length - 1];

  /** The bundler-shaped receipt for whatever identity was actually submitted. */
  const userOperationReceipt = (hash) => {
    const prepared = submitted();
    if (!prepared || prepared.userOperationHash !== hash) return null;
    return {
      userOperationHash: hash,
      entryPoint: prepared.entryPoint.address,
      sender: prepared.userOperation.sender,
      nonce: quantity(BigInt(prepared.userOperation.nonce)),
      paymaster: ZERO_ADDRESS,
      actualGasCost: "0x9",
      actualGasUsed: "0xa",
      success: true,
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(INCLUSION_BLOCK),
      blockHash: BLOCK_HASH,
    };
  };

  const transactionReceipt = () => {
    const prepared = submitted();
    if (!prepared) return null;
    return {
      transactionHash: TRANSACTION_HASH,
      blockNumber: quantity(INCLUSION_BLOCK),
      blockHash: BLOCK_HASH,
      transactionIndex: "0x0",
      status: "0x1",
      logs: [
        {
          address: prepared.entryPoint.address,
          blockNumber: quantity(INCLUSION_BLOCK),
          blockHash: BLOCK_HASH,
          transactionHash: TRANSACTION_HASH,
          transactionIndex: "0x0",
          logIndex: "0x0",
          removed: false,
          topics: [
            USER_OPERATION_EVENT,
            prepared.userOperationHash,
            `0x${"0".repeat(24)}${prepared.userOperation.sender.slice(2)}`,
            `0x${"0".repeat(24)}${ZERO_ADDRESS.slice(2)}`,
          ],
          data: `0x${word(BigInt(prepared.userOperation.nonce))}${word(1n)}${word(9n)}${word(10n)}`,
        },
      ],
    };
  };

  return {
    label: "injected facts (no network)",
    validator: VALIDATOR,
    sends,
    stop: () => {},
    capability: {
      chainId,
      reads: {
        async read(request) {
          if (request.type === "chain_id") return request.chainId;
          if (request.type === "code") return request.address === ACCOUNT ? "0x" : "0x01";
          if (request.type === "runtime_code_hash") {
            if (request.address === KERNEL_V4_ENTRY_POINT_V07) {
              return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
            }
            return request.address === KERNEL_V4_UUPS_IMPLEMENTATION_V07
              ? deployment.implementationDeployment.runtimeCodeHash
              : KERNEL_V4_FACTORY_V07_CODE_HASH;
          }
          if (request.type === "kernel_factory_account") return ACCOUNT;
          return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
        },
      },
      observation: {
        async read(request) {
          if (request.type === "chain_id") return chainId;
          if (request.type === "user_operation_receipt") {
            return userOperationReceipt(request.userOperationHash);
          }
          if (request.type === "transaction_receipt") return transactionReceipt();
          if (request.type === "transaction") {
            const prepared = submitted();
            return prepared === undefined
              ? null
              : {
                  hash: TRANSACTION_HASH,
                  to: prepared.entryPoint.address,
                  blockNumber: quantity(INCLUSION_BLOCK),
                  blockHash: BLOCK_HASH,
                  transactionIndex: "0x0",
                };
          }
          // Finality equals inclusion here, so the ancestor walk is one block.
          if (
            request.type === "finalized_block" ||
            request.type === "canonical_block" ||
            request.type === "block_by_hash"
          ) {
            return inclusionBlock;
          }
          // A replacement search needs an indexer; this example submits one
          // operation per lane and never claims to have looked.
          if (request.type === "replacement_candidate") return null;
          throw new Error(`unsupported observation read ${request.type}`);
        },
        async close() {},
      },
      bundler: {
        async probe(request) {
          return {
            accepting: true,
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
              return { userOperationHash: request.prepared.userOperationHash };
            },
            async close() {},
          };
        },
      },
      async quote() {
        return {
          nonceKey: "0",
          sequence: String(sends.length),
          gas: {
            callGasLimit: "100000",
            verificationGasLimit: "200000",
            preVerificationGas: "50000",
            maxFeePerGas: "1000000000",
            maxPriorityFeePerGas: "100000000",
          },
        };
      },
      // Complete finalized usage evidence from this chain's own record of what
      // it included: every send in this fake finalizes at the inclusion block,
      // so the finalized count is the send count. Without this evidence,
      // coverage is inconclusive and sendCalls is denied — absent evidence is
      // never read as "unused", and it never widens to owner authority.
      async usage(request) {
        return {
          version: "oaath.grant-policy-usage/v1",
          status: "complete",
          grantId: request.grantId,
          chainId: request.chainId,
          finalizedOperationCount: String(sends.length),
          through: {
            blockNumber: INCLUSION_BLOCK.toString(10),
            blockHash: BLOCK_HASH,
            observedAt: 1_800_000_000,
          },
        };
      },
      feePayer: null,
    },
  };
}
