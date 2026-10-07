import {
  type KernelRuntimeModule,
  kernelDeployment,
  prepareRuntimeModuleDeployment,
} from "@oaath/sdk/kernel";
import type { Hex } from "cetane";
import { getCreate2Address, keccak256 } from "cetane/utils";
import runtime from "../../contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import validity from "../../contracts/artifacts/OaathKernelV4ValidityPolicy.json" with {
  type: "json",
};

export interface Component {
  readonly id: string;
  readonly address: Hex;
  readonly required: boolean;
  /** Needed only by WebAuthn (passkey) sessions. */
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
  const salt = input.slice(0, 66) as Hex;
  if (salt !== `0x${"00".repeat(32)}`) throw new Error(`Nonzero deployment salt: ${id}`);
  const address = getCreate2Address({
    from: create2Deployer,
    salt,
    bytecodeHash: keccak256(`0x${input.slice(66)}`),
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

/** The SDK owns the OAAth runtime modules' deployment transactions. */
function runtimeModule(chainId: number, id: string, module: KernelRuntimeModule, passkey = false) {
  const prepared = prepareRuntimeModuleDeployment({ chainId, module });
  if (prepared === null) throw new Error(`External runtime module: ${module}`);
  return [
    id,
    { deploymentInput: prepared.data, runtimeCodeHash: prepared.expectedRuntimeCodeHash },
    prepared.address,
    !passkey,
    passkey,
  ] as const;
}

/** Externally owned module deployments are prerequisites, never CLI transactions. */
function externalComponent(
  id: string,
  artifact: { expectedAddress: string; runtimeCodeHash: string },
  passkey = false,
): Component {
  return {
    id,
    address: artifact.expectedAddress as Hex,
    runtimeCodeHash: artifact.runtimeCodeHash as Hex,
    required: !passkey,
    passkeySession: passkey,
    deploymentInput: null,
  };
}

export function components(chainId: number): readonly Component[] {
  const deployment = kernelDeployment({ chainId });
  const deployable = (...args: DeployableArgs) =>
    deployableComponent(deployment.create2Deployer, ...args);
  return [
    {
      id: "entryPoint",
      address: deployment.entryPoint.address,
      required: true,
      passkeySession: false,
      runtimeCodeHash: null,
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
    deployable("kernelUups", runtime.kernelUups, deployment.implementation),
    deployable("kernelImmutableEcdsa", runtime.kernelImmutableEcdsa, null),
    deployable(
      "kernelFactory",
      { ...runtime.kernelFactory, runtimeCodeHash: deployment.factoryRuntimeCodeHash },
      deployment.factory,
    ),
    deployable(...runtimeModule(chainId, "validityPolicy", "validity_policy")),
    externalComponent("callPolicy", runtime.callPolicy),
    externalComponent("rateLimitPolicy", runtime.rateLimitPolicy),
    deployable(...runtimeModule(chainId, "resettingRateLimitPolicy", "rate_limit_policy")),
    externalComponent("ecdsaSigner", runtime.ecdsaSigner),
    deployable(
      "p256Validator",
      runtime.p256Validator,
      runtime.p256Validator.expectedAddress,
      false,
    ),
    deployable(...runtimeModule(chainId, "webAuthnSigner", "webauthn_signer", true)),
    // The pinned WebAuthn signer always verifies through this singleton.
    externalComponent("p256Verifier", runtime.p256Verifier, true),
  ];
}
