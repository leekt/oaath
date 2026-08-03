import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import {
  getKernelAddressFromECDSA,
  getValidatorAddress,
  signerToEcdsaValidator,
} from "@zerodev/ecdsa-validator";
import { PasskeyValidatorContractVersion } from "@zerodev/passkey-validator";
import { ECDSA_SIGNER_CONTRACT } from "@zerodev/permissions";
import { toECDSASigner, toSignerId } from "@zerodev/permissions/signers";
import { createKernelAccount, createKernelAccountClient, uninstallPlugin } from "@zerodev/sdk";
import { DUMMY_ECDSA_SIG, KERNEL_V3_3 } from "@zerodev/sdk/constants";
import { createWalletClient } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { describe, expect, it, vi } from "vitest";
import {
  createEcdsaKernelOwnerRuntime,
  createEcdsaPermissionSignerRuntime,
  createLocalKernelHandleOpsAdapter,
  createLocalKernelPermissionUninstallAdapter,
  createP256KernelOwnerRuntime,
  createWebAuthnKernelOwnerRuntime,
  getKernelRuntimeCapability,
  KERNEL_RUNTIME_CAPABILITIES,
  OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION,
  OgpKernelRuntimeCapabilitiesError,
} from "../src/index.js";

const require = createRequire(import.meta.url);

function installedPackageVersion(packageName: string): string {
  const entry = require.resolve(packageName);
  const manifestPath = join(dirname(dirname(entry)), "package.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { version?: unknown };
  if (typeof manifest.version !== "string") throw new Error(`${packageName} has no version`);
  return manifest.version;
}

function expectDeeplyFrozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectDeeplyFrozen(child);
}

function collectKeys(value: unknown, keys = new Set<string>()): Set<string> {
  if (value === null || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    keys.add(key.toLowerCase());
    collectKeys(child, keys);
  }
  return keys;
}

describe("Kernel runtime capabilities", () => {
  it("pins the exact installed public artifacts and accepted protocol releases", () => {
    expect(OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION).toBe("ogp.kernel-runtime-capabilities/v1");
    expect(installedPackageVersion("@zerodev/sdk")).toBe("5.5.10");
    expect(installedPackageVersion("@zerodev/permissions")).toBe("5.6.3");
    expect(installedPackageVersion("@zerodev/ecdsa-validator")).toBe("5.4.9");
    expect(installedPackageVersion("@zerodev/passkey-validator")).toBe("5.6.0");
    expect(installedPackageVersion("@zerodev/webauthn-key")).toBe("5.5.0");
    expect(installedPackageVersion("viem")).toBe("2.55.8");
    expect(typeof createKernelAccount).toBe("function");
    expect(typeof createKernelAccountClient).toBe("function");
    expect(typeof uninstallPlugin).toBe("function");
    expect(typeof getKernelAddressFromECDSA).toBe("function");
    expect(typeof getValidatorAddress).toBe("function");
    expect(typeof signerToEcdsaValidator).toBe("function");
    expect(ECDSA_SIGNER_CONTRACT).toBe("0x6A6F069E2a08c2468e7724Ab3250CdBFBA14D4FF");
    expect(typeof toECDSASigner).toBe("function");
    expect(typeof toSignerId).toBe("function");
    expect(typeof createEcdsaPermissionSignerRuntime).toBe("function");
    expect(typeof createEcdsaKernelOwnerRuntime).toBe("function");
    expect(typeof createP256KernelOwnerRuntime).toBe("function");
    expect(typeof createWebAuthnKernelOwnerRuntime).toBe("function");
    expect(PasskeyValidatorContractVersion.V0_0_3_PATCHED).toBe("0.0.3");
    expect(typeof createWalletClient).toBe("function");
    expect(typeof createLocalKernelHandleOpsAdapter).toBe("function");
    expect(typeof createLocalKernelPermissionUninstallAdapter).toBe("function");
    expect(DUMMY_ECDSA_SIG).toMatch(/^0x[0-9a-f]{130}$/u);
    expect(KERNEL_V3_3).toBe("0.3.3");
    expect(
      entryPoint07Abi.some((item) => item.type === "function" && item.name === "handleOps"),
    ).toBe(true);

    expect(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevSdk).toMatchObject({
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
          names: ["DUMMY_ECDSA_SIG", "KERNEL_V3_3"],
        },
      ],
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.packages.viem).toMatchObject({
      packageName: "viem",
      packageVersion: "2.55.8",
      integrity:
        "sha512-BHqtsmK4iMLuLnRyrPIB1jVrmFVliRIP/K0dnFT7gBOpfo8Ko4ozhkzUCRNfR+Z/ZZdnlnVrh04fAOuIm5Svkg==",
      shasum: "38858031b543b20d2330e74ec534fde89c39a4c7",
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevEcdsaValidator).toMatchObject({
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
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevPermissions).toMatchObject({
      packageName: "@zerodev/permissions",
      packageVersion: "5.6.3",
      integrity:
        "sha512-MwW3Eo3rB5ViOKdY6NUoyvmQTV/bCbOZbmQMTYQqAT7B8rdI9jo44nNONMOHIhDkfF4VFhQ9+M50cCZLA/6zcg==",
      shasum: "69ae470e03d5a750e6b3484c82d5e854e127523a",
      npmGitHead: "6db091cc65c74526e22980a3754776618c2e3a7e",
      source: {
        repository: "https://github.com/zerodevapp/sdk",
        path: "plugins/permission",
        commit: "6db091cc65c74526e22980a3754776618c2e3a7e",
        packageVersion: "5.6.2",
        alignment: "registry_version_differs_from_git_head_tree",
      },
      publicExports: [
        {
          importPath: "@zerodev/permissions",
          names: ["ECDSA_SIGNER_CONTRACT"],
        },
        {
          importPath: "@zerodev/permissions/signers",
          names: ["toECDSASigner", "toSignerId"],
        },
      ],
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevPasskeyValidator).toMatchObject({
      packageName: "@zerodev/passkey-validator",
      packageVersion: "5.6.0",
      integrity:
        "sha512-ItnPs/6m3pT8tWaLqt31AFFQ4tAc5O01gtXP0Y7RW7xfuqUbgwYOghyeKMEkw6LfYykUWLhapL4B5c0CBYkgvg==",
      shasum: "d01de6ebf550c532cae8508bf625e234dc4e5a1e",
      npmGitHead: "5bf80dc1764e239e26a6af7d281a4618ed043e1e",
      source: {
        commit: "f61e9ca59e7ef71dedf5619a93c4799e4c9a5a65",
        packageVersion: "5.6.0",
        alignment: "registry_git_head_differs_from_published_source_tree",
      },
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevWebAuthnKey).toMatchObject({
      packageName: "@zerodev/webauthn-key",
      packageVersion: "5.5.0",
      integrity:
        "sha512-AbD2d/qrsX7AWxJMEfwxnLbp1TjiUjc1V4ne3Q40UJxKe+lW64Td+y8OD0qSFMqgN6rQxJZ0aOAXmat8H6xluA==",
      shasum: "5300d4e1eed20a73aa6844d32a272697cc45baeb",
      npmGitHead: "11143912ea1d9da965ce8b86e0982bd798f06544",
    });
    expect(KERNEL_RUNTIME_CAPABILITIES.contracts).toEqual({
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
    });
  });

  it("reports only the exact installed capability substrate as available", () => {
    expect(
      Object.fromEntries(
        Object.entries(KERNEL_RUNTIME_CAPABILITIES.capabilities).map(([profile, result]) => [
          profile,
          result.status,
        ]),
      ),
    ).toEqual({
      kernel_account: "available",
      owner_ecdsa: "available",
      owner_p256: "available",
      owner_webauthn: "available",
      permission_signer_ecdsa: "available",
      permission_signer_p256: "unsupported",
      permission_signer_webauthn: "unsupported",
      replayable_all_chain_permission_approval: "unsupported",
      permission_install: "unsupported",
      permission_uninstall: "available",
      bundler_submission: "available",
      entrypoint_handle_ops_submission: "available",
    });

    expect(getKernelRuntimeCapability("kernel_account")).toEqual({
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccount", "zerodev_sdk.KERNEL_V3_3", "kernel.v3_3"],
      constraints: ["compatible_plugin_manager_required"],
    });
    expect(getKernelRuntimeCapability("owner_ecdsa")).toEqual({
      status: "available",
      anchors: [
        "zerodev_ecdsa_validator.getKernelAddressFromECDSA",
        "zerodev_ecdsa_validator.signerToEcdsaValidator",
        "ogp.createEcdsaKernelOwnerRuntime",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
    });
    expect(getKernelRuntimeCapability("owner_p256")).toEqual({
      status: "available",
      anchors: [
        "leekt_p256_validator.P256Validator",
        "ogp.createP256KernelOwnerRuntime",
        "zerodev_sdk.createKernelAccount",
        "zerodev_sdk.KERNEL_V3_3",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
      constraints: ["action_runtime_and_precompile_evidence_required"],
    });
    expect(getKernelRuntimeCapability("owner_webauthn")).toEqual({
      status: "available",
      anchors: [
        "zerodev_passkey_validator.toPasskeyValidator",
        "zerodev_passkey_validator.V0_0_3_PATCHED",
        "ogp.createWebAuthnKernelOwnerRuntime",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
    });
    expect(getKernelRuntimeCapability("permission_signer_ecdsa")).toEqual({
      status: "available",
      anchors: [
        "zerodev_permissions.ECDSA_SIGNER_CONTRACT",
        "zerodev_sdk.DUMMY_ECDSA_SIG",
        "ogp.createEcdsaPermissionSignerRuntime",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
    });
    expect(getKernelRuntimeCapability("bundler_submission")).toEqual({
      status: "available",
      anchors: ["zerodev_sdk.createKernelAccountClient"],
    });
    expect(getKernelRuntimeCapability("entrypoint_handle_ops_submission")).toEqual({
      status: "available",
      anchors: [
        "ogp.createLocalKernelHandleOpsAdapter",
        "viem.createWalletClient",
        "viem.entryPoint07Abi",
        "entrypoint.v0_7",
      ],
    });
    expect(getKernelRuntimeCapability("permission_uninstall")).toEqual({
      status: "available",
      anchors: [
        "zerodev_sdk.uninstallPlugin",
        "ogp.createLocalKernelPermissionUninstallAdapter",
        "kernel.v3_3",
      ],
    });
  });

  it("fails closed for remaining unavailable credentials, permission install, and approval", () => {
    expect(getKernelRuntimeCapability("permission_install")).toMatchObject({
      status: "unsupported",
      reason: "integration_unproven",
      constraints: ["generic_plugin_primitive_only"],
    });
    expect(getKernelRuntimeCapability("replayable_all_chain_permission_approval")).toEqual({
      status: "unsupported",
      reason: "incompatible_approval_shape",
      constraints: ["verifying_contract_address_bound", "finite_account_enumeration_only"],
    });
  });

  it("keeps raw P-256 distinct from WebAuthn", () => {
    expect(getKernelRuntimeCapability("owner_p256")).toMatchObject({ status: "available" });
    expect(getKernelRuntimeCapability("permission_signer_p256")).toEqual({
      status: "unsupported",
      reason: "distinct_profile_unproven",
      constraints: ["webauthn_is_not_raw_p256"],
    });
    expect(getKernelRuntimeCapability("owner_webauthn")).toMatchObject({ status: "available" });
    expect(getKernelRuntimeCapability("permission_signer_webauthn")).toMatchObject({
      status: "unsupported",
      reason: "integration_unproven",
    });
  });

  it("is deeply immutable, localizes deployment evidence, and has no chain inventory", () => {
    expectDeeplyFrozen(KERNEL_RUNTIME_CAPABILITIES);
    expect(
      Reflect.set(KERNEL_RUNTIME_CAPABILITIES.packages.zerodevSdk, "packageVersion", "next"),
    ).toBe(false);

    const forbiddenKeys = new Set(["chainids", "chains", "supportedchains", "default", "fallback"]);
    for (const key of collectKeys(KERNEL_RUNTIME_CAPABILITIES)) {
      expect(forbiddenKeys.has(key), `forbidden manifest key: ${key}`).toBe(false);
    }
    expect(KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator.deploymentEvidence.chainId).toBe(
      11_155_111,
    );
  });

  it("rejects unknown or hostile queries without consulting object properties", () => {
    const getter = vi.fn();
    const object = Object.defineProperty({}, "profile", { get: getter });
    const proxy = new Proxy(
      {},
      {
        get() {
          throw new Error("query property was read");
        },
        ownKeys() {
          throw new Error("query keys were read");
        },
      },
    );

    for (const value of [undefined, null, 1, object, proxy, "unknown", "__proto__"]) {
      try {
        getKernelRuntimeCapability(value);
        throw new Error("expected capability query to fail");
      } catch (error) {
        expect(error).toBeInstanceOf(OgpKernelRuntimeCapabilitiesError);
        expect(error).toMatchObject({ code: "kernel_runtime_profile_invalid" });
      }
    }
    expect(getter).not.toHaveBeenCalled();
  });

  it("exposes the manifest only through the package root", () => {
    expect(() => import.meta.resolve("@leekt/ogp/kernel-runtime-capabilities")).toThrowError(
      /Package subpath|not defined by "exports"/u,
    );
  });
});
