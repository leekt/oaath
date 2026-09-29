import {
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  kernelV4Deployment,
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
function deployable(
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
    from: KERNEL_V4_CREATE2_DEPLOYER,
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
  const implementationHash = kernelV4Deployment(chainId).implementationDeployment?.runtimeCodeHash;
  return [
    {
      id: "entryPoint",
      address: KERNEL_V4_ENTRY_POINT_V07,
      required: true,
      passkeySession: false,
      runtimeCodeHash: KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
      deploymentInput: null,
    },
    {
      id: "create2Deployer",
      address: KERNEL_V4_CREATE2_DEPLOYER,
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
      KERNEL_V4_UUPS_IMPLEMENTATION_V07,
    ),
    deployable("kernelImmutableEcdsa", runtime.kernelImmutableEcdsa, null),
    deployable(
      "kernelFactory",
      { ...runtime.kernelFactory, runtimeCodeHash: KERNEL_V4_FACTORY_V07_CODE_HASH },
      KERNEL_V4_FACTORY_V07,
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
