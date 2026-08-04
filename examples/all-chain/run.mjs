/**
 * Approve before chain B exists, then materialize on B.
 *
 * One owner signature — counted on the credential itself — deploys the account,
 * installs the scoped permission, and authorizes the session's first call on
 * chain A; then chain B is started, and the *same* signature bytes do the same
 * thing there. No second owner approval, no per-chain consent.
 *
 * The reason it works is that the approval covers a chain-independent digest over
 * (account, install nonce, installed packages), and every address in the stack is
 * CREATE2-derived, so the account address and the permission are identical on both
 * chains. What stays chain-local is everything that must: the nonce, the operation
 * identity, inclusion, and revocation evidence.
 *
 * Requires Anvil (`foundryup`). Two chains × the full Kernel stack takes ~20s.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  materializeKernelPermission,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk";
import { parseEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { anvilAvailable, deployKernelStack, startAnvil } from "../support/anvil.mjs";

const CHAIN_A = 421_614;
const CHAIN_B = 11_155_111;
/** Kernel's own install nonce for this one approval: per-chain state, same value. */
const INSTALL_NONCE = "0";
const TRANSFER = "500";
const GAS = {
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};

if (!anvilAvailable()) {
  console.error("all-chain example: Anvil is required and was not found.");
  console.error("  install Foundry (https://getfoundry.sh) or set ANVIL_PATH, then re-run:");
  console.error("  node examples/all-chain/run.mjs");
  process.exit(1);
}

const say = (...parts) => console.log(...parts);
const step = (title) => say(`\n▸ ${title}`);
const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};
const lower = (value) => value.toLowerCase();

/**
 * One owner credential that counts its own signing invocations. The count is the
 * evidence: an implementation that quietly re-approved per chain would show two.
 */
const ownerKeyAccount = privateKeyToAccount(generatePrivateKey());
let ownerSignatures = 0;
const owner = {
  address: ownerKeyAccount.address,
  sign: async (request) => {
    ownerSignatures += 1;
    return ownerKeyAccount.sign(request);
  },
};

/** One session credential and one scope, shared by every chain. */
const sessionKeyAccount = privateKeyToAccount(generatePrivateKey());
const sessionTarget = lower(privateKeyToAccount(generatePrivateKey()).address);

const chains = [];

/** Brings up one chain and composes the owner and session runtimes over it. */
async function bringUp(chainId) {
  const chain = await startAnvil(chainId);
  chains.push(chain);
  const stack = await deployKernelStack(chain);
  const deployment = kernelV4Deployment(chainId);
  const ownerRuntime = createKernelRuntime({
    deployment,
    operator: ownerOperator({ key: ecdsaKey({ account: owner, validator: stack.validator }) }),
    reads: stack.reads,
  });
  const sessionRuntime = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: ecdsaKey({ account: sessionKeyAccount, validator: stack.validator }),
      // The approved scope: this target with empty calldata, at most 500 wei.
      policies: [
        { kind: "call", calls: [{ target: sessionTarget, selectors: ["0x00000000"] }] },
        { kind: "value", maximumValue: TRANSFER },
      ],
    }),
    reads: stack.reads,
  });
  // The session binds the account the owner's root packages define, so the
  // address depends on the owner authority and never on the session.
  const account = await sessionRuntime.bindAccount({
    accountIndex: "0",
    initialPackages: ownerRuntime.packages,
  });
  await stack.fund(account.account, parseEther("1"));
  return { chain, stack, ownerRuntime, sessionRuntime, account };
}

/** Materializes the approval on one chain and executes the covered call. */
async function materializeAndExecute(target, grantId) {
  const materialized = await materializeKernelPermission({
    approval,
    runtime: target.sessionRuntime,
    grantId,
    account: target.account,
    nonceKey: "0",
    sequence: "0",
    calls: [{ target: sessionTarget, value: TRANSFER, data: "0x" }],
    gas: GAS,
  });
  expect(
    materialized.prepared.chainId === target.chain.chainId,
    "the prepared operation is bound to another chain",
  );
  // The one owner signature is carried into the envelope verbatim on every chain.
  expect(
    materialized.signature.includes(approval.enableSignature.slice(2)),
    "the submitted envelope does not carry the owner's approval signature",
  );
  const sent = await target.stack.sendSigned(materialized.prepared, materialized.signature);
  expect(sent.status === "success", `the materializing operation ${sent.status}`);
  const balance = await target.chain.client.getBalance({ address: sessionTarget });
  expect(balance === BigInt(TRANSFER), `the covered call moved ${balance} wei`);
  return materialized;
}

let approval;
try {
  step(`chain A (${CHAIN_A}) — the only chain that exists yet`);
  const a = await bringUp(CHAIN_A);
  expect(a.account.state === "counterfactual", `chain A account is ${a.account.state}`);
  say(`  account          ${a.account.account} (counterfactual)`);
  say(`  validator        ${a.stack.validator}`);

  step("one owner approval");
  // It reads no chain and no deployment profile: nothing here can depend on a
  // chain that exists, let alone on one that does not.
  approval = await approveKernelPermissionAllChain({
    owner: ecdsaKey({ account: owner, validator: a.stack.validator }),
    account: a.account.account,
    installNonce: INSTALL_NONCE,
    packages: a.sessionRuntime.packages,
  });
  expect(ownerSignatures === 1, `the owner signed ${ownerSignatures} times`);
  expect(
    approval.digest ===
      kernelV4ReplayableInstallDigest({
        account: a.account.account,
        nonce: INSTALL_NONCE,
        packages: a.sessionRuntime.packages,
      }),
    "the approval digest is not reproducible from its own chain-independent fields",
  );
  say(`  digest           ${approval.digest}`);
  say("  covers           every supported chain, including chains not yet started");

  step("execute on chain A");
  const materializedA = await materializeAndExecute(a, "grant-a");
  say(`  operation        ${materializedA.prepared.userOperationHash}`);
  say("  one submission   deployed the account, installed the permission, executed the call");
  expect(ownerSignatures === 1, "chain A asked the owner again");

  step(`introduce chain B (${CHAIN_B}) — started only now, after the approval exists`);
  const b = await bringUp(CHAIN_B);
  expect(b.chain.chainId !== a.chain.chainId, "both chains report the same chain id");
  expect(b.account.account === a.account.account, "the account address differs across chains");
  expect(
    JSON.stringify(b.sessionRuntime.packages) === JSON.stringify(a.sessionRuntime.packages),
    "the installed packages differ across chains",
  );
  say(`  account          ${b.account.account} (identical, CREATE2-derived)`);
  say("  permission       one scope, one permission id, on both chains");

  step("the same signature materializes on chain B");
  const materializedB = await materializeAndExecute(b, "grant-b");
  expect(
    materializedB.signature !== materializedA.signature,
    "the two operations carry the same signature envelope",
  );
  expect(
    materializedB.prepared.userOperationHash !== materializedA.prepared.userOperationHash,
    "the two chains share one operation identity",
  );
  expect(ownerSignatures === 1, `the owner signed ${ownerSignatures} times`);
  say(`  operation        ${materializedB.prepared.userOperationHash} (chain-local identity)`);
  say(`  owner signatures ${ownerSignatures} — the same approval bytes, replayed`);

  say("\nall-chain example: ok");
} catch (error) {
  console.error("\nall-chain example: FAILED");
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const chain of chains) chain.stop();
}
