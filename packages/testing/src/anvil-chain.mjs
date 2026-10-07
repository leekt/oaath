/**
 * The five chain ports, answered by a real local chain: a chain capability is
 * the whole boundary between the SDK and a network.
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

import { encodeKernelNonceKey, encodeKernelNonceRead } from "@oaath/sdk/advanced";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import { kernelDeployment } from "@oaath/sdk/kernel";
import {
  createLocalAnvilObservation,
  readLocalOperationReceipt,
  readLocalPermissionInstalled,
} from "./anvil-observation.mjs";
import { deployKernelStack, startAnvil } from "./anvil-process.mjs";
import { deployLocalV33Account } from "./anvil-v33.js";

/** Generous fixed limits: a devnet needs no estimation to prove the journey. */
const GAS = {
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};

/**
 * @param {number} chainId
 * @param {{ p256?: boolean, existingOwner?: import("cetane").Hex | null }} [options]
 */
export async function createAnvilChain(chainId, options = {}) {
  const { p256 = false, existingOwner = null } = options;
  const chain = await startAnvil(chainId, p256 ? "osaka" : "prague");
  try {
    const stack = await deployKernelStack(chain, { p256 });
    const existingAccount =
      existingOwner === null ? null : await deployLocalV33Account(chain, stack, existingOwner);
    const deployment = kernelDeployment({
      chainId,
      kernelVersion: existingAccount === null ? "0.4.0" : "0.3.3",
    });
    // Use only the public read port here; this fixture owns submission below.
    const reads = createCetaneChainPorts({
      [chainId]: { publicRpcUrls: [chain.url], bundlerUrl: chain.url },
    })[0].reads;
    const feePayerBalance = await chain.client.getBalance({ address: stack.submitter.address });
    const sends = [];
    const userOperationReceipt = (hash) =>
      readLocalOperationReceipt(chain, deployment.entryPoint.address, hash);
    const permissionInstalled = (request) => readLocalPermissionInstalled(chain, request);

    async function nonceQuote(request) {
      // The SDK names the lane; revocation quotes use the default namespace.
      const nonceKey = request.nonceKey ?? "0";
      const key =
        existingAccount === null
          ? encodeKernelNonceKey({
              deployment,
              mode: request.mode,
              validation: request.validation,
              nonceKey,
            })
          : encodeKernelNonceKey({
              deployment,
              mode: request.mode === "enable-replayable" ? "enable" : "standard",
              validation: request.validation,
              nonceKey,
            });
      const raw = await chain.rpc("eth_call", [
        {
          to: deployment.entryPoint.address,
          data: encodeKernelNonceRead({ account: request.account, key }),
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
      url: chain.url,
      processId: chain.processId,
      label: `local Anvil at ${chain.url} with Kernel ${existingAccount === null ? "v4" : "v3.3"}`,
      validator:
        existingAccount === null
          ? stack.validator
          : kernelDeployment({ chainId, kernelVersion: "0.3.3" }).ecdsaValidator,
      existingAccount,
      sends,
      fund: (account) => stack.fund(account, 10n ** 18n),
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
        if (installed !== true && installed !== false)
          throw new Error("permission_state_unreadable");
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
        reads,
        observation: createLocalAnvilObservation(chain, deployment.entryPoint.address),
        // The bundler + handleOps-fallback configuration. A devnet runs no
        // bundler: its probe reports `absent`, a fact rather than a failure,
        // and that is what authorizes the handleOps route after it.
        routes: [
          {
            kind: /** @type {const} */ ("erc4337-bundler"),
            bundler: {
              async probe(request) {
                return {
                  accepting: false,
                  chainId: request.chainId,
                  supportedEntryPoints: [request.entryPoint],
                };
              },
            },
          },
          {
            kind: /** @type {const} */ ("erc4337-handleops"),
            feePayer: {
              address: stack.submitter.address.toLowerCase(),
              balance: feePayerBalance.toString(10),
            },
          },
        ],
        submission: {
          async open(request) {
            sends.push(request.prepared);
            return {
              async send() {
                const sent = await stack.sendSigned(request.prepared, request.signature);
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
          await stack.fund(request.account, 10n ** 18n);
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
      },
    };
  } catch {
    chain.stop();
    throw new Error("local_chain_start_failed");
  }
}
