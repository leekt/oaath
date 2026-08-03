export const OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION =
  "ogp.kernel-runtime-capabilities/v1" as const;

export type KernelRuntimeProfile =
  | "kernel_account"
  | "owner_ecdsa"
  | "owner_p256"
  | "owner_webauthn"
  | "permission_signer_ecdsa"
  | "permission_signer_p256"
  | "permission_signer_webauthn"
  | "replayable_all_chain_permission_approval"
  | "permission_install"
  | "permission_uninstall"
  | "bundler_submission"
  | "entrypoint_handle_ops_submission";

export type KernelRuntimeAnchorId =
  | "zerodev_sdk.createKernelAccount"
  | "zerodev_sdk.KERNEL_V3_3"
  | "zerodev_sdk.createKernelAccountClient"
  | "viem.entryPoint07Abi"
  | "kernel.v3_3"
  | "entrypoint.v0_7";

export type KernelRuntimeUnsupportedReason =
  | "package_not_installed"
  | "distinct_profile_unproven"
  | "incompatible_approval_shape";

export type KernelRuntimeConstraint =
  | "compatible_plugin_manager_required"
  | "generic_plugin_primitive_only"
  | "verifying_contract_address_bound"
  | "finite_account_enumeration_only"
  | "webauthn_is_not_raw_p256";

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
        readonly importPath: "viem/account-abstraction";
        readonly names: readonly ["entryPoint07Abi"];
      }[];
    };
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
          names: ["createKernelAccount", "createKernelAccountClient"],
        },
        {
          importPath: "@zerodev/sdk/constants",
          names: ["KERNEL_V3_3"],
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
          importPath: "viem/account-abstraction",
          names: ["entryPoint07Abi"],
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
  },
  capabilities: {
    kernel_account: {
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccount", "zerodev_sdk.KERNEL_V3_3", "kernel.v3_3"],
      constraints: ["compatible_plugin_manager_required"],
    },
    owner_ecdsa: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/ecdsa-validator"],
    },
    owner_p256: {
      status: "unsupported",
      reason: "distinct_profile_unproven",
      constraints: ["webauthn_is_not_raw_p256"],
    },
    owner_webauthn: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/passkey-validator", "@zerodev/webauthn-key"],
    },
    permission_signer_ecdsa: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/permissions"],
    },
    permission_signer_p256: {
      status: "unsupported",
      reason: "distinct_profile_unproven",
      constraints: ["webauthn_is_not_raw_p256"],
    },
    permission_signer_webauthn: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/permissions"],
    },
    replayable_all_chain_permission_approval: {
      status: "unsupported",
      reason: "incompatible_approval_shape",
      constraints: ["verifying_contract_address_bound", "finite_account_enumeration_only"],
    },
    permission_install: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/permissions"],
      constraints: ["generic_plugin_primitive_only"],
    },
    permission_uninstall: {
      status: "unsupported",
      reason: "package_not_installed",
      requiredPackages: ["@zerodev/permissions"],
      constraints: ["generic_plugin_primitive_only"],
    },
    bundler_submission: {
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccountClient"],
    },
    entrypoint_handle_ops_submission: {
      status: "available",
      anchors: ["viem.entryPoint07Abi", "entrypoint.v0_7"],
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
