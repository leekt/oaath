import {
  kernelDeployment,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
  pinnedPolicyModule,
  pinnedSignerModule,
} from "@oaath/sdk/kernel";
import { getCreate2Address, type Hex, sliceHex } from "viem";
import runtime from "../../contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import validity from "../../contracts/artifacts/OaathKernelV4ValidityPolicy.json" with {
  type: "json",
};
// The SDK owns this reproducible artifact and checks it against its pinned hash.
import resettingRateLimit from "../../sdk/test/fixtures/kernel-rate-limit-deployment.json" with {
  type: "json",
};

export interface Component {
  readonly id: string;
  readonly address: Hex;
  readonly required: boolean;
  /** Needed only by WebAuthn (passkey) sessions; deploy-runtime deploys it too. */
  readonly passkeySession: boolean;
  readonly runtimeCodeHash: Hex | null;
  readonly deploymentInput: Hex | null;
}

// CREATE2 inputs live with the contracts. No test validator is packaged here.
type DeployableArgs = [
  id: string,
  artifact: { deploymentInput: string; runtimeCodeHash?: string },
  expectedAddress: string | null,
  required?: boolean,
  passkeySession?: boolean,
];

function deployableComponent(
  create2Deployer: Hex,
  id: string,
  artifact: { deploymentInput: string; runtimeCodeHash?: string },
  expectedAddress: string | null,
  required = true,
  passkeySession = false,
): Component {
  const input = artifact.deploymentInput as Hex;
  const salt = sliceHex(input, 0, 32);
  if (salt !== `0x${"00".repeat(32)}`) throw new Error(`Nonzero deployment salt: ${id}`);
  const address = getCreate2Address({
    from: create2Deployer,
    salt,
    bytecode: sliceHex(input, 32),
  }).toLowerCase() as Hex;
  if (expectedAddress !== null && address !== expectedAddress.toLowerCase())
    throw new Error(`Deployment address mismatch: ${id}`);
  return {
    id,
    address,
    required,
    passkeySession,
    runtimeCodeHash: (artifact.runtimeCodeHash as Hex | undefined) ?? null,
    deploymentInput: input,
  };
}

export function components(chainId: number): readonly Component[] {
  const deployment = kernelDeployment({ chainId });
  const implementationHash = deployment.implementationDeployment?.runtimeCodeHash;
  const deployable = (...args: DeployableArgs) =>
    deployableComponent(deployment.create2Deployer, ...args);
  return [
    {
      id: "entryPoint",
      address: deployment.entryPoint.address,
      required: true,
      passkeySession: false,
      runtimeCodeHash: deployment.entryPoint.runtimeCodeHash,
      deploymentInput: null,
    },
    {
      id: "create2Deployer",
      address: deployment.create2Deployer,
      required: true,
      passkeySession: false,
      runtimeCodeHash: validity.deployment.deployerRuntimeCodeHash as Hex,
      deploymentInput: null,
    },
    deployable(
      "kernelUups",
      {
        ...runtime.kernelUups,
        ...(implementationHash ? { runtimeCodeHash: implementationHash } : {}),
      },
      deployment.implementation,
    ),
    deployable("kernelImmutableEcdsa", runtime.kernelImmutableEcdsa, null),
    deployable(
      "kernelFactory",
      { ...runtime.kernelFactory, runtimeCodeHash: deployment.factoryRuntimeCodeHash },
      deployment.factory,
    ),
    deployable("validityPolicy", validity.deployment, pinnedPolicyModule("expiry")),
    deployable("callPolicy", runtime.callPolicy, pinnedPolicyModule("call")),
    deployable("rateLimitPolicy", runtime.rateLimitPolicy, pinnedPolicyModule("operation-limit")),
    deployable(
      "resettingRateLimitPolicy",
      { ...resettingRateLimit, runtimeCodeHash: OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH },
      pinnedPolicyModule("rate-limit"),
    ),
    deployable("ecdsaSigner", runtime.ecdsaSigner, pinnedSignerModule("ecdsa")),
    deployable(
      "p256Validator",
      runtime.p256Validator,
      runtime.p256Validator.expectedAddress,
      false,
    ),
    deployable(
      "webAuthnSigner",
      runtime.webAuthnSigner,
      pinnedSignerModule("webauthn"),
      false,
      true,
    ),
    // The pinned WebAuthn signer always verifies through this singleton.
    deployable(
      "p256Verifier",
      runtime.p256Verifier,
      runtime.p256Verifier.expectedAddress,
      false,
      true,
    ),
  ];
}
