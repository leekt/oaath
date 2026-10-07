/**
 * A portal account is factory-derived Kernel 0.4.0 with one ECDSA, raw P-256 or
 * WebAuthn root. For each kind, the root approves a dapp session's permission
 * through prepareKernelPermissionApproval, and the session's first operation
 * installs it in enable mode and executes a covered call on a local chain.
 */
import { readFile } from "node:fs/promises";
import type { Hex } from "viem";
import { parseEther } from "viem";
import { afterAll, describe, expect, it } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { ECDSA_VALIDATOR } from "../src/kernel/deployment/v33.js";
import { credentialKey } from "../src/kernel/key/credential.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { KERNEL_WEBAUTHN_VALIDATOR } from "../src/kernel/modules.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import { deriveSessionPolicyProfiles } from "../src/kernel/permission/profiles.js";
import {
  kernelDeployment,
  materializeKernelPermission,
  prepareKernelPermissionApproval,
} from "../src/kernel.js";
import { type AnvilChain, createHarness, deployKernelStack, startAnvil } from "./support/anvil.js";
import {
  type PortalRootKind,
  portalPermissionRequest,
  portalRoot,
  portalSession,
} from "./support/portal-roots.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const CHAIN_ID = 8_453;
const gas = Object.freeze({
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
});

const chains: AnvilChain[] = [];
afterAll(() => {
  for (const chain of chains) chain.stop();
});

async function json(path: string) {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

/** Osaka carries the P-256 precompile the pinned raw P-256 validator requires. */
async function portalChain() {
  const chain = await startAnvil(CHAIN_ID, "osaka");
  chains.push(chain);
  const harness = await createHarness(chain);
  await deployKernelStack(harness);
  for (const module of [
    harness.fixture.p256Validator,
    harness.fixture.ecdsaSigner,
    harness.fixture.callPolicy,
    harness.fixture.validityPolicy,
    harness.fixture.rateLimitPolicy,
  ])
    await harness.deployModule(module);
  // The deployment-bound ECDSA root validator and the reviewed WebAuthn validator.
  const v33 = await json("./fixtures/kernel-v33-deployments.json");
  await harness.deployCreate2(v33.ecdsaValidator.deploymentInput as Hex);
  const webauthn = await json("../../contracts/artifacts/KernelWebAuthnValidator.json");
  await harness.deployCreate2(webauthn.deploymentInput as Hex);
  expect(await harness.client.getCode({ address: ECDSA_VALIDATOR })).toBeTruthy();
  expect(await harness.client.getCode({ address: KERNEL_WEBAUTHN_VALIDATOR })).toBeTruthy();
  return harness;
}

(requireAnvil ? describe : describe.skip)("portal account roots approve a dapp session", () => {
  it.each<PortalRootKind>(["ecdsa", "p256", "webauthn"])(
    "%s root: prepare, refuse a non-root key, sign, then enable and execute on first use",
    async (kind) => {
      const harness = await portalChain();
      const root = portalRoot(kind);
      const now = Number((await harness.client.getBlock()).timestamp);
      const target = `0x${"7a".repeat(20)}` as const;
      const request = portalPermissionRequest({ root, target, requestedAt: now });
      const prepared = await prepareKernelPermissionApproval({
        request,
        chainId: CHAIN_ID,
        reads: harness.reads,
      });
      expect(prepared.signingRequest.signer.ownerCredential).toEqual(root.credential);

      // Another key of the same kind is refused before it is asked to sign.
      await expect(prepared.sign(portalRoot(kind, "other").key, now)).rejects.toMatchObject({
        code: "kernel_runtime_binding_mismatch",
      });

      const decision = await prepared.sign(root.key, now);
      const approval = decision.installApproval;
      expect(approval.digest).toBe(prepared.signingRequest.expectedDigest);
      expect(approval.account).toBe(prepared.signingRequest.signer.account);
      expect(await harness.client.getCode({ address: approval.account })).toBeFalsy();
      await harness.fund(approval.account, parseEther("1"));

      const deployment = kernelDeployment({ chainId: CHAIN_ID });
      const owner = createKernelRuntime({
        deployment,
        operator: ownerOperator({
          key: credentialKey({ credential: root.credential, validator: root.validator }),
        }),
        reads: harness.reads,
      });
      const session = createKernelRuntime({
        deployment,
        operator: sessionOperator({
          key: ecdsaKey({ account: portalSession(), validator: ECDSA_VALIDATOR }),
          policies: deriveSessionPolicyProfiles(request.policy),
        }),
        reads: harness.reads,
      });
      const first = await materializeKernelPermission({
        approval,
        runtime: session,
        grantId: request.requestId,
        account: await session.bindAccount({
          accountIndex: "0",
          initialPackages: owner.packages,
        }),
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "500", data: "0x12345678" }],
        gas,
      });
      expect(first.prepared.userOperation.factory).not.toBeNull();
      expect(await harness.sendSigned(first.prepared, first.signature)).toBe("success");
      expect(await harness.client.getBalance({ address: target })).toBe(500n);
      expect(await harness.client.getCode({ address: approval.account })).toBeTruthy();
    },
    120_000,
  );
});
