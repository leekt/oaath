export const OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION =
  "ogp.kernel-runtime-capabilities/v1" as const;

export type KernelRuntimeProfile =
  | "kernel_account"
  | "kernel_validator_ecdsa"
  | "kernel_validator_p256"
  | "kernel_validator_webauthn"
  | "replayable_all_chain_permission_approval"
  | "permission_install"
  | "permission_uninstall"
  | "bundler_submission"
  | "entrypoint_handle_ops_submission";

export type KernelRuntimeAnchorId =
  | "zerodev_sdk.createKernelAccount"
  | "zerodev_sdk.KERNEL_V3_3"
  | "zerodev_sdk.VALIDATOR_TYPE.SECONDARY"
  | "zerodev_sdk.createKernelAccountClient"
  | "zerodev_sdk.uninstallPlugin"
  | "zerodev_ecdsa_validator.signerToEcdsaValidator"
  | "zerodev_passkey_validator.toPasskeyValidator"
  | "zerodev_passkey_validator.V0_0_3_PATCHED"
  | "viem.createWalletClient"
  | "viem.entryPoint07Abi"
  | "ogp.createKernelOperator"
  | "ogp.createKernelOwner"
  | "ogp.toEcdsaKernelSigner"
  | "ogp.toP256KernelSigner"
  | "ogp.toWebAuthnKernelSigner"
  | "ogp.createLocalKernelHandleOpsAdapter"
  | "ogp.createLocalKernelPermissionUninstallAdapter"
  | "kernel.v3_3"
  | "entrypoint.v0_7"
  | "leekt_p256_validator.P256Validator";

export type KernelRuntimeUnsupportedReason =
  | "package_not_installed"
  | "integration_unproven"
  | "incompatible_approval_shape";

export type KernelRuntimeConstraint =
  | "action_runtime_and_precompile_evidence_required"
  | "compatible_plugin_manager_required"
  | "generic_plugin_primitive_only"
  | "kernel_secondary_validator_only"
  | "verifying_contract_address_bound"
  | "finite_account_enumeration_only";

interface AvailableKernelRuntimeCapability {
  readonly status: "available";
  readonly anchors: readonly KernelRuntimeAnchorId[];
  readonly constraints?: readonly KernelRuntimeConstraint[];
}

interface UnsupportedKernelRuntimeCapability {
  readonly status: "unsupported";
  readonly reason: KernelRuntimeUnsupportedReason;
  readonly requiredPackages?: readonly string[];
  readonly constraints?: readonly KernelRuntimeConstraint[];
}

type KernelRuntimeCapabilityShape =
  | AvailableKernelRuntimeCapability
  | UnsupportedKernelRuntimeCapability;

type PublishedPackageShape = Readonly<{
  packageName: string;
  packageVersion: string;
  integrity: `sha512-${string}`;
  shasum: string;
  npmGitHead: string;
  source: Readonly<
    Record<"repository" | "path" | "commit" | "packageVersion" | "alignment", string>
  >;
  publicExports: readonly Readonly<{ importPath: string; names: readonly string[] }>[];
}>;

interface KernelRuntimeCapabilitiesManifestShape {
  readonly version: typeof OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION;
  readonly packages: {
    readonly zerodevSdk: {
      readonly packageName: "@zerodev/sdk";
      readonly packageVersion: "5.5.10";
      readonly integrity: `sha512-${string}`;
      readonly shasum: string;
      readonly npmGitHead: string;
      readonly source: {
        readonly repository: "https://github.com/zerodevapp/sdk";
        readonly path: "packages/core";
        readonly commit: string;
        readonly packageVersion: "5.5.9";
        readonly tag: null;
        readonly alignment: "registry_version_differs_from_git_head_tree";
      };
      readonly publicExports: readonly {
        readonly importPath: string;
        readonly names: readonly string[];
      }[];
    };
    readonly viem: {
      readonly packageName: "viem";
      readonly packageVersion: "2.55.8";
      readonly integrity: `sha512-${string}`;
      readonly shasum: string;
      readonly publicExports: readonly {
        readonly importPath: string;
        readonly names: readonly string[];
      }[];
    };
    readonly zerodevEcdsaValidator: {
      readonly packageName: "@zerodev/ecdsa-validator";
      readonly packageVersion: "5.4.9";
      readonly integrity: `sha512-${string}`;
      readonly shasum: string;
      readonly npmGitHead: string;
      readonly source: {
        readonly repository: "https://github.com/zerodevapp/sdk";
        readonly path: "plugins/ecdsa";
        readonly commit: string;
        readonly packageVersion: "5.4.8";
        readonly tag: null;
        readonly alignment: "registry_version_differs_from_git_head_tree";
      };
      readonly publicExports: readonly {
        readonly importPath: "@zerodev/ecdsa-validator";
        readonly names: readonly string[];
      }[];
    };
    readonly zerodevPasskeyValidator: PublishedPackageShape;
    readonly zerodevWebAuthnKey: PublishedPackageShape;
  };
  readonly contracts: {
    readonly kernel: {
      readonly version: "0.3.3";
      readonly repository: "https://github.com/zerodevapp/kernel";
      readonly releaseTag: "v3.3";
      readonly commit: string;
      readonly implementation: `0x${string}`;
      readonly factory: `0x${string}`;
      readonly metaFactory: `0x${string}`;
    };
    readonly entryPoint: {
      readonly version: "0.7";
      readonly repository: "https://github.com/eth-infinitism/account-abstraction";
      readonly releaseTag: "v0.7.0";
      readonly commit: string;
      readonly address: `0x${string}`;
    };
    readonly webauthnValidator: {
      readonly version: "0.0.3";
      readonly status: "patched";
      readonly address: `0x${string}`;
      readonly runtimeKeccak256: `0x${string}`;
      readonly runtimeByteLength: 4739;
      readonly verifiedSource: string;
      readonly compiler: "0.8.30";
      readonly optimizerRuns: 20000;
      readonly evmVersion: "london";
    };
    readonly p256Verifier: {
      readonly kind: "daimo";
      readonly address: `0x${string}`;
      readonly runtimeKeccak256: `0x${string}`;
      readonly runtimeByteLength: 3537;
    };
    readonly p256Validator: {
      readonly repository: "https://github.com/leekt/P256Validator";
      readonly sourceCommit: string;
      readonly deploymentEvidenceCommit: string;
      readonly address: `0x${string}`;
      readonly runtimeKeccak256: `0x${string}`;
      readonly runtimeByteLength: 1919;
      readonly compiler: "0.8.26";
      readonly optimizerRuns: 200;
      readonly evmVersion: "osaka";
      readonly p256Precompile: `0x${string}`;
      readonly deploymentEvidence: {
        readonly chainId: 11155111;
        readonly transactionHash: `0x${string}`;
        readonly deployer: `0x${string}`;
        readonly salt: `0x${string}`;
      };
    };
  };
  readonly capabilities: Readonly<Record<KernelRuntimeProfile, KernelRuntimeCapabilityShape>>;
}

type DeepReadonly<Value> = Value extends (...args: never[]) => unknown
  ? Value
  : Value extends readonly unknown[]
    ? { readonly [Key in keyof Value]: DeepReadonly<Value[Key]> }
    : Value extends object
      ? { readonly [Key in keyof Value]: DeepReadonly<Value[Key]> }
      : Value;

function deepFreeze<Value extends object>(value: Value): DeepReadonly<Value> {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object" && !Object.isFrozen(child)) {
      deepFreeze(child);
    }
  }
  return Object.freeze(value) as DeepReadonly<Value>;
}

const manifest = {
  version: OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION,
  packages: {
    zerodevSdk: {
      packageName: "@zerodev/sdk",
      packageVersion: "5.5.10",
      integrity:
        "sha512-WVyj2XR9F6zK2GdXrvappx7yo6zoJ46cWe42dOIArp3xDjFBninjA4O1O94MwohB0G+yFqtXNsEU+WxdE67SgQ==",
      shasum: "694d6088fa577266bd21fbfee2eba8eaf66c1051",
      npmGitHead: "427e48a759dec1216bca4d533dc46538d033f734",
      source: {
        repository: "https://github.com/zerodevapp/sdk",
        path: "packages/core",
        commit: "427e48a759dec1216bca4d533dc46538d033f734",
        packageVersion: "5.5.9",
        tag: null,
        alignment: "registry_version_differs_from_git_head_tree",
      },
      publicExports: [
        {
          importPath: "@zerodev/sdk",
          names: ["createKernelAccount", "createKernelAccountClient", "uninstallPlugin"],
        },
        {
          importPath: "@zerodev/sdk/constants",
          names: ["KERNEL_V3_3", "VALIDATOR_TYPE"],
        },
      ],
    },
    viem: {
      packageName: "viem",
      packageVersion: "2.55.8",
      integrity:
        "sha512-BHqtsmK4iMLuLnRyrPIB1jVrmFVliRIP/K0dnFT7gBOpfo8Ko4ozhkzUCRNfR+Z/ZZdnlnVrh04fAOuIm5Svkg==",
      shasum: "38858031b543b20d2330e74ec534fde89c39a4c7",
      publicExports: [
        {
          importPath: "viem",
          names: ["createWalletClient"],
        },
        {
          importPath: "viem/account-abstraction",
          names: ["entryPoint07Abi"],
        },
      ],
    },
    zerodevEcdsaValidator: {
      packageName: "@zerodev/ecdsa-validator",
      packageVersion: "5.4.9",
      integrity:
        "sha512-9NVE8/sQIKRo42UOoYKkNdmmHJY8VlT4t+2MHD2ipLg21cpbY9fS17TGZh61+Bl3qlqc8pP23I6f89z9im7kuA==",
      shasum: "106226ac90f52f780f146037a4f1e32f6ccbe3a6",
      npmGitHead: "8de7ce47e525459a39e731cfe6045d808dd8bb6e",
      source: {
        repository: "https://github.com/zerodevapp/sdk",
        path: "plugins/ecdsa",
        commit: "8de7ce47e525459a39e731cfe6045d808dd8bb6e",
        packageVersion: "5.4.8",
        tag: null,
        alignment: "registry_version_differs_from_git_head_tree",
      },
      publicExports: [
        {
          importPath: "@zerodev/ecdsa-validator",
          names: ["signerToEcdsaValidator"],
        },
      ],
    },
    zerodevPasskeyValidator: {
      packageName: "@zerodev/passkey-validator",
      packageVersion: "5.6.0",
      integrity:
        "sha512-ItnPs/6m3pT8tWaLqt31AFFQ4tAc5O01gtXP0Y7RW7xfuqUbgwYOghyeKMEkw6LfYykUWLhapL4B5c0CBYkgvg==",
      shasum: "d01de6ebf550c532cae8508bf625e234dc4e5a1e",
      npmGitHead: "5bf80dc1764e239e26a6af7d281a4618ed043e1e",
      source: {
        repository: "https://github.com/zerodevapp/sdk",
        path: "plugins/passkey",
        commit: "f61e9ca59e7ef71dedf5619a93c4799e4c9a5a65",
        packageVersion: "5.6.0",
        alignment: "registry_git_head_differs_from_published_source_tree",
      },
      publicExports: [
        {
          importPath: "@zerodev/passkey-validator",
          names: ["PasskeyValidatorContractVersion", "toPasskeyValidator"],
        },
      ],
    },
    zerodevWebAuthnKey: {
      packageName: "@zerodev/webauthn-key",
      packageVersion: "5.5.0",
      integrity:
        "sha512-AbD2d/qrsX7AWxJMEfwxnLbp1TjiUjc1V4ne3Q40UJxKe+lW64Td+y8OD0qSFMqgN6rQxJZ0aOAXmat8H6xluA==",
      shasum: "5300d4e1eed20a73aa6844d32a272697cc45baeb",
      npmGitHead: "11143912ea1d9da965ce8b86e0982bd798f06544",
      source: {
        repository: "https://github.com/zerodevapp/sdk",
        path: "plugins/webauthn-key",
        commit: "f61e9ca59e7ef71dedf5619a93c4799e4c9a5a65",
        packageVersion: "5.5.0",
        alignment: "registry_git_head_differs_from_published_source_tree",
      },
      publicExports: [
        {
          importPath: "@zerodev/webauthn-key",
          names: ["b64ToBytes", "base64FromUint8Array"],
        },
      ],
    },
  },
  contracts: {
    kernel: {
      version: "0.3.3",
      repository: "https://github.com/zerodevapp/kernel",
      releaseTag: "v3.3",
      commit: "cd697c7e21715d015e0643af22310a99aa17433b",
      implementation: "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28",
      factory: "0x2577507b78c2008Ff367261CB6285d44ba5eF2E9",
      metaFactory: "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
    },
    entryPoint: {
      version: "0.7",
      repository: "https://github.com/eth-infinitism/account-abstraction",
      releaseTag: "v0.7.0",
      commit: "7af70c8993a6f42973f520ae0752386a5032abe7",
      address: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    },
    webauthnValidator: {
      version: "0.0.3",
      status: "patched",
      address: "0x7ab16Ff354AcB328452F1D445b3Ddee9a91e9e69",
      runtimeKeccak256: "0x726d987ac55574f77f5184326631c5c51142f94c16c9b9281b751f97519c9eea",
      runtimeByteLength: 4739,
      verifiedSource:
        "https://etherscan.io/address/0x7ab16ff354acb328452f1d445b3ddee9a91e9e69#code",
      compiler: "0.8.30",
      optimizerRuns: 20000,
      evmVersion: "london",
    },
    p256Verifier: {
      kind: "daimo",
      address: "0xc2b78104907F722DABAc4C69f826a522B2754De4",
      runtimeKeccak256: "0x3cd725b6ba67b40b7979190c41a015e82cf21e098eb61832ba623f8538bab7fc",
      runtimeByteLength: 3537,
    },
    p256Validator: {
      repository: "https://github.com/leekt/P256Validator",
      sourceCommit: "8f6a71992e297f2e7caa61df2c6eb0b6d9145d2d",
      deploymentEvidenceCommit: "4be442538977b6b81453656d2f8f4938431d7d65",
      address: "0x9906AB44fF795883C5a725687A2705BE4118B0f3",
      runtimeKeccak256: "0xd7d9a5b1ddd1e22e7235268fd624c7c0714e5046b199d507bbfe5e03408e579d",
      runtimeByteLength: 1919,
      compiler: "0.8.26",
      optimizerRuns: 200,
      evmVersion: "osaka",
      p256Precompile: "0x0000000000000000000000000000000000000100",
      deploymentEvidence: {
        chainId: 11155111,
        transactionHash: "0xcc3381af97315ffae6ac17477f5cf0f8cc7e905f114fc2d545b5d6e9543094ca",
        deployer: "0x4e59b44847b379578588920cA78FbF26c0B4956C",
        salt: "0x0000000000000000000000000000000000000000000000000000000000000000",
      },
    },
  },
  capabilities: {
    kernel_account: {
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccount", "zerodev_sdk.KERNEL_V3_3", "kernel.v3_3"],
      constraints: ["compatible_plugin_manager_required"],
    },
    kernel_validator_ecdsa: {
      status: "available",
      anchors: [
        "zerodev_ecdsa_validator.signerToEcdsaValidator",
        "ogp.toEcdsaKernelSigner",
        "ogp.createKernelOwner",
        "ogp.createKernelOperator",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
    },
    kernel_validator_p256: {
      status: "available",
      anchors: [
        "leekt_p256_validator.P256Validator",
        "zerodev_sdk.VALIDATOR_TYPE.SECONDARY",
        "ogp.toP256KernelSigner",
        "ogp.createKernelOwner",
        "ogp.createKernelOperator",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
      constraints: [
        "kernel_secondary_validator_only",
        "action_runtime_and_precompile_evidence_required",
      ],
    },
    kernel_validator_webauthn: {
      status: "available",
      anchors: [
        "zerodev_passkey_validator.toPasskeyValidator",
        "zerodev_passkey_validator.V0_0_3_PATCHED",
        "ogp.toWebAuthnKernelSigner",
        "ogp.createKernelOwner",
        "ogp.createKernelOperator",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
    },
    replayable_all_chain_permission_approval: {
      status: "unsupported",
      reason: "incompatible_approval_shape",
      constraints: ["verifying_contract_address_bound", "finite_account_enumeration_only"],
    },
    permission_install: {
      status: "unsupported",
      reason: "integration_unproven",
      constraints: ["generic_plugin_primitive_only"],
    },
    permission_uninstall: {
      status: "available",
      anchors: [
        "zerodev_sdk.uninstallPlugin",
        "ogp.createLocalKernelPermissionUninstallAdapter",
        "kernel.v3_3",
      ],
    },
    bundler_submission: {
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccountClient"],
    },
    entrypoint_handle_ops_submission: {
      status: "available",
      anchors: [
        "ogp.createLocalKernelHandleOpsAdapter",
        "viem.createWalletClient",
        "viem.entryPoint07Abi",
        "entrypoint.v0_7",
      ],
    },
  },
} as const satisfies KernelRuntimeCapabilitiesManifestShape;

export const KERNEL_RUNTIME_CAPABILITIES = deepFreeze(manifest);

export type KernelRuntimeCapabilitiesManifest = typeof KERNEL_RUNTIME_CAPABILITIES;
export type KernelRuntimeCapability =
  KernelRuntimeCapabilitiesManifest["capabilities"][KernelRuntimeProfile];

export type KernelRuntimeCapabilitiesErrorCode = "kernel_runtime_profile_invalid";

export class OgpKernelRuntimeCapabilitiesError extends Error {
  readonly code: KernelRuntimeCapabilitiesErrorCode;

  constructor() {
    super("kernel runtime profile must be a known identifier");
    this.name = "OgpKernelRuntimeCapabilitiesError";
    this.code = "kernel_runtime_profile_invalid";
  }
}

export function getKernelRuntimeCapability(profile: unknown): Readonly<KernelRuntimeCapability> {
  if (
    typeof profile !== "string" ||
    !Object.hasOwn(KERNEL_RUNTIME_CAPABILITIES.capabilities, profile)
  ) {
    throw new OgpKernelRuntimeCapabilitiesError();
  }
  return KERNEL_RUNTIME_CAPABILITIES.capabilities[profile as KernelRuntimeProfile];
}
