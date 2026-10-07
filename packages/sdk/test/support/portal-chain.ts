/**
 * A local Anvil chain with everything a portal account's root needs: the Kernel
 * stack, the ECDSA, raw P-256 and WebAuthn root validators, and the modules a
 * dapp session's permission installs.
 */
import { readFile } from "node:fs/promises";
import type { Hex } from "viem";
import { expect } from "vitest";
import { ECDSA_VALIDATOR } from "../../src/kernel/deployment/v33.js";
import { KERNEL_WEBAUTHN_VALIDATOR } from "../../src/kernel/modules.js";
import {
  type AnvilChain,
  createHarness,
  deployKernelStack,
  type KernelHarness,
  startAnvil,
} from "./anvil.js";

async function json(path: string) {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

/** Osaka carries the P-256 precompile the pinned raw P-256 validator requires. */
export async function startPortalChain(
  chainId: number,
  chains: AnvilChain[],
): Promise<KernelHarness> {
  const chain = await startAnvil(chainId, "osaka");
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
  const v33 = await json("../fixtures/kernel-v33-deployments.json");
  await harness.deployCreate2(v33.ecdsaValidator.deploymentInput as Hex);
  const webauthn = await json("../../../contracts/artifacts/KernelWebAuthnValidator.json");
  await harness.deployCreate2(webauthn.deploymentInput as Hex);
  expect(await harness.client.getCode({ address: ECDSA_VALIDATOR })).toBeTruthy();
  expect(await harness.client.getCode({ address: KERNEL_WEBAUTHN_VALIDATOR })).toBeTruthy();
  return harness;
}
