/**
 * One local Anvil chain carrying the pinned Kernel v4 stack.
 *
 * ponytail: this is a minimal inlined copy of `packages/sdk/test/support/anvil.ts`,
 * whose own header carries the consolidation marker — both copies collapse into
 * `@oaath/testing`'s chain fixtures when that package's `anvil.ts` lands, and the
 * examples will import it from there. The contract artifacts own the deployment
 * bytecode; the ECDSA validator mock stays separate and test-only.
 *
 * Every address here is CREATE2-derived, so two chains started from this module
 * carry the identical stack at the identical addresses — which is what makes one
 * all-chain owner approval replayable across them.
 *
 * @author taek <leekt216@gmail.com>
 */

import { spawn, spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { encodeHandleOps } from "@oaath/sdk/advanced";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import { kernelDeployment } from "@oaath/sdk/kernel";
import { createPublicClient, createWalletClient, http } from "cetane";
import { privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
import { concatHex, getCreate2Address, keccak256 } from "cetane/utils";
import runtime from "../../contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import validity from "../../contracts/artifacts/OaathKernelV4ValidityPolicy.json" with {
  type: "json",
};
import ecdsaValidator from "../../sdk/test/fixtures/kernel-ecdsa-mock.json" with { type: "json" };

import resettingRateLimit from "../../sdk/test/fixtures/kernel-rate-limit-deployment.json" with {
  type: "json",
};

const fixture = { ...runtime, ecdsaValidator, validityPolicy: validity.deployment };

/** Kernel v4 pins no ECDSA validator, so the examples deploy one under this salt. */
const VALIDATOR_SALT = `0x${"00".repeat(32)}`;

/** True when the `anvil` binary can actually be executed. */
export function anvilAvailable() {
  const probe = spawnSync(process.env.ANVIL_PATH ?? "anvil", ["--version"], { stdio: "ignore" });
  return probe.error === undefined && probe.status === 0;
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

/**
 * Starts one loopback Anvil bound to `chainId`, or throws if Anvil is absent.
 *
 * The hardfork is a parameter because one module's dependency is a chain
 * feature rather than a deployment: the pinned raw P-256 validator staticcalls
 * the RIP-7212 / EIP-7951 precompile at 0x100, which Prague does not carry and
 * Osaka does. The phone demo asks for `osaka`; everything else keeps Prague.
 * @returns {Promise<{ chainId: number, url: string, processId: number | undefined, client: ReturnType<typeof createPublicClient>, rpc: (method: string, params?: unknown[]) => Promise<any>, stop: () => void }>}
 */
export async function startAnvil(chainId, hardfork = "prague") {
  const port = await reservePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(
    process.env.ANVIL_PATH ?? "anvil",
    [
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--chain-id",
      String(chainId),
      "--hardfork",
      hardfork,
      "--accounts",
      "0",
      // A devnet finalizes nothing by default: its `finalized` tag never leaves
      // genesis. One slot per epoch makes the real tag follow the chain, two
      // blocks behind, so observation can prove finality from the node itself
      // instead of from an assumption this example made up.
      "--slots-in-an-epoch",
      "1",
      // Anvil derives its clock offset from a genesis timestamp it reads before
      // its clock starts; a second boundary between the two reads leaves every
      // block a second behind wall time, so a wall-clock validAfter (AA22) is
      // not yet due. An explicit genesis one second ahead keeps chain time at or
      // ahead of wall time unless startup itself takes over a second.
      "--timestamp",
      String(Math.floor(Date.now() / 1000) + 1),
      "--silent",
    ],
    { stdio: "ignore" },
  );
  child.once("error", () => {});
  /** @type {ReturnType<typeof createPublicClient>} */
  const client = createPublicClient({
    chain: { id: chainId, name: "Anvil", nativeAA: false },
    transport: http(url),
  });
  for (let attempt = 0; ; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Anvil exited before chain ${chainId} was ready`);
    try {
      if ((await client.getChainId({ refresh: true })) === chainId) break;
    } catch {
      if (attempt >= 200) {
        child.kill("SIGTERM");
        throw new Error(`Anvil did not become ready for chain ${chainId}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  return {
    chainId,
    url,
    processId: child.pid,
    client,
    rpc: async (method, params) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      const body = await response.json();
      if (body.error) throw new Error("local_rpc_failed");
      return body.result;
    },
    stop: () => child.kill("SIGTERM"),
  };
}

/**
 * Deploys EntryPoint 0.9, both Kernel v4 implementations, the factory, the pinned
 * policy and signer modules, and one ECDSA validator, and returns the funded
 * submitter every direct `EntryPoint.handleOps` submission uses.
 * @returns {Promise<{
 *   submitter: ReturnType<typeof privateKeyToAccount>,
 *   wallet: ReturnType<typeof createWalletClient>,
 *   validator: import("cetane").Address,
 *   reads: import("@oaath/sdk/kernel").KernelReads,
 *   fund: (address: import("cetane").Address, value: bigint) => Promise<void>,
 *   sendSigned: (prepared: import("@oaath/sdk/kernel").PreparedUserOperation, signature: import("cetane").Hex, onTransactionHash?: (hash: import("cetane").Hex) => void) => Promise<{ status: string, transactionHash: import("cetane").Hex, userOperationHash: import("cetane").Hex, evidence: object }>
 * }>}
 */
export async function deployKernelStack(chain, { p256 = false } = {}) {
  const deployer = kernelDeployment({ chainId: chain.chainId }).create2Deployer;
  const submitter = privateKeyToAccount(`0x${"c0ffee".padEnd(64, "0")}`);
  /** @type {ReturnType<typeof createWalletClient>} */
  const wallet = createWalletClient({
    chain: { id: chain.chainId, name: "Anvil", nativeAA: false, execution: createExecution() },
    account: { address: submitter.address },
    signer: submitter,
    transport: http(chain.url),
  });
  const setBalance = async (address, value) =>
    chain.rpc("anvil_setBalance", [address, `0x${value.toString(16)}`]);
  await setBalance(submitter.address, 1000n * 10n ** 18n);

  const deploy = async (deploymentInput) => {
    const hash = await wallet.sendTransaction({
      to: deployer,
      data: deploymentInput,
      gas: 10_000_000n,
    });
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error("a CREATE2 deployment reverted");
  };

  await deploy(fixture.entryPoint.deploymentInput);
  for (const input of [fixture.kernelUups, fixture.kernelImmutableEcdsa, fixture.kernelFactory]) {
    await deploy(input.deploymentInput);
  }
  for (const module of [
    fixture.ecdsaSigner,
    fixture.webAuthnSigner,
    // The WebAuthn signer's software P-256 verifier; passkey sessions require it.
    fixture.p256Verifier,
    fixture.callPolicy,
    fixture.validityPolicy,
    fixture.rateLimitPolicy,
    resettingRateLimit,
    // The pinned P-256 validator's constructor probes the RIP-7212 precompile
    // and reverts without it, so it deploys only on an osaka chain that asked.
    ...(p256 ? [fixture.p256Validator] : []),
  ]) {
    await deploy(module.deploymentInput);
  }
  /** @type {import("cetane").Address} */
  const validator = getCreate2Address({
    from: deployer,
    salt: VALIDATOR_SALT,
    bytecodeHash: keccak256(fixture.ecdsaValidator.bytecode),
  }).toLowerCase();
  await deploy(concatHex([VALIDATOR_SALT, fixture.ecdsaValidator.bytecode]));

  return {
    submitter,
    wallet,
    validator,
    reads: createCetaneChainPorts({ [chain.chainId]: { publicRpcUrls: [chain.url] } })[0].reads,
    fund: async (address, value) => setBalance(address, value),
    /**
     * Submits one prepared operation and the signature produced for it through
     * `EntryPoint.handleOps`, which is the route a chain with no bundler leaves.
     * `encodeHandleOps` re-derives the operation hash while packing, so the
     * identity cannot drift between preparing and submitting.
     */
    sendSigned: async (prepared, signature, onTransactionHash = () => {}) => {
      const call = encodeHandleOps({ prepared, signature, beneficiary: submitter.address });
      const hash = await wallet.sendTransaction({
        to: call.entryPoint,
        data: call.data,
        gas: 8_000_000n,
      });
      // The outer hash exists before receipt waiting can fail. Expose it at that
      // exact boundary so operation owners retain evidence and observe only.
      onTransactionHash(hash);
      const receipt = await chain.client.waitForTransactionReceipt({ hash });
      return {
        status: receipt.status,
        transactionHash: hash,
        userOperationHash: call.userOperationHash,
        evidence: Object.freeze({
          chainId: chain.chainId,
          account: prepared.userOperation.sender,
          userOperationHash: call.userOperationHash,
          transactionHash: hash,
          blockHash: receipt.blockHash,
          blockNumber: `0x${receipt.blockNumber.toString(16)}`,
          status: receipt.status === "success" ? "included" : "reverted",
        }),
      };
    },
  };
}
