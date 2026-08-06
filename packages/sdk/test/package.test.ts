/**
 * The five published surfaces, pinned name for name. The root entry teaches
 * exactly one product path; everything infrastructural is an explicit subpath
 * a consumer must opt into.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import * as advanced from "../src/advanced.js";
import * as root from "../src/index.js";
import * as kernel from "../src/kernel.js";
import * as persistence from "../src/persistence.js";
import * as testing from "../src/testing.js";
import * as viem from "../src/viem.js";

describe("package boundary", () => {
  it("exposes only the adopter workflow on the root entry", () => {
    expect(Object.keys(root).sort()).toEqual(["OaathClientError", "createOAAth"]);
  });

  it("exposes the reviewed Kernel primitives on /kernel", () => {
    expect(Object.keys(kernel).sort()).toEqual([
      "KERNEL_V4_CREATE2_DEPLOYER",
      "KERNEL_V4_ENTRY_POINT_V07",
      "KERNEL_V4_ENTRY_POINT_V07_CODE_HASH",
      "KERNEL_V4_EXECUTE_SELECTOR",
      "KERNEL_V4_EXECUTE_USER_OP_SELECTOR",
      "KERNEL_V4_FACTORY_V07",
      "KERNEL_V4_FACTORY_V07_CODE_HASH",
      "KERNEL_V4_IMPLEMENTATION_SLOT",
      "KERNEL_V4_UUPS_IMPLEMENTATION_V07",
      "OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION",
      "OAATH_PREPARED_USER_OPERATION_VERSION",
      "OaathKernelRuntimeError",
      "OaathKernelV4Error",
      "OaathPreparedUserOperationError",
      "approveKernelPermissionAllChain",
      "asViemUserOperation",
      "bindKernelV4Account",
      "compileKernelPermissionPolicy",
      "createKernelRuntime",
      "createKernelV4Reads",
      "deriveOperationId",
      "diagnoseKernelCapability",
      "ecdsaKey",
      "encodeKernelV4EnableSignature",
      "encodeKernelV4Execution",
      "encodeKernelV4FactoryAddressRead",
      "encodeKernelV4FactoryDeploy",
      "encodeKernelV4FactoryImplementationRead",
      "encodeKernelV4Initialize",
      "encodeKernelV4InstallModules",
      "encodeKernelV4Nonce",
      "encodeKernelV4NonceKey",
      "encodeKernelV4NonceRead",
      "encodeKernelV4PermissionSignature",
      "encodeKernelV4PermissionUninstallCalls",
      "encodeKernelV4PolicyData",
      "encodeKernelV4SignerData",
      "encodeKernelV4ValidatorData",
      "kernelAllChainCapabilityHash",
      "kernelV4Deployment",
      "kernelV4ReplayableInstallDigest",
      "materializeKernelPermission",
      "ownerOperator",
      "p256Key",
      "parseKernelAllChainApproval",
      "parsePreparedUserOperation",
      "pinnedPolicyModule",
      "pinnedSignerModule",
      "prepareKernelV4UserOperation",
      "prepareUserOperation",
      "sessionOperator",
      "webauthnKey",
    ]);
  });

  it("exposes custom-deployment ports on /advanced", () => {
    expect(Object.keys(advanced).sort()).toEqual([
      "GrantStore",
      "OAATH_BINDING_HASH_DOMAIN",
      "OAATH_BINDING_VERSION",
      "OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES",
      "OAATH_GRANT_STORE_RECORD_VERSION",
      "OAATH_HANDLE_OPS_OVERHEAD_GAS",
      "OAATH_OPERATION_STORE_RECORD_VERSION",
      "OaathCleanupError",
      "OaathOperationObserverError",
      "OaathOperationRunnerError",
      "OaathRoutingError",
      "OaathStoreError",
      "OperationStore",
      "captureOaathBinding",
      "captureRoutingCapabilities",
      "classifyBundlerAcceptance",
      "classifyBundlerProbe",
      "closeEffect",
      "createOperationObserver",
      "createOperationRunner",
      "decideExecution",
      "deriveHandleOpsRequirement",
      "deriveOperationPrefund",
      "deriveSessionPolicyProfiles",
      "encodeHandleOps",
      "forgetLocalEffect",
      "prepareSponsoredKernelOperation",
      "probeBundlerCapability",
      "revokeEffect",
      "runOaathCleanup",
      "signOutEffect",
    ]);
  });

  it("exposes durable adapters and record contracts on /persistence", () => {
    expect(Object.keys(persistence).sort()).toEqual([
      "OAATH_CLEANUP_CHECKPOINT_VERSION",
      "OAATH_CLIENT_CONTEXT_VERSION",
      "OAATH_INDEXEDDB_NAME",
      "OAATH_INDEXEDDB_STORES",
      "OAATH_INDEXEDDB_VERSION",
      "OaathPersistenceError",
      "createIndexedDbCleanupStore",
      "createIndexedDbContextStore",
      "createIndexedDbGrantStoreAdapter",
      "createIndexedDbKeyStore",
      "createIndexedDbOperationStoreAdapter",
      "isCleanupEffectName",
      "openOaathDatabase",
      "parseCleanupCheckpoint",
      "parseClientContext",
      "requireNonExtractableKey",
    ]);
  });

  it("exposes only deterministic memory stores on /testing", () => {
    expect(Object.keys(testing).sort()).toEqual([
      "createMemoryCleanupStore",
      "createMemoryContextStore",
      "createMemoryGrantStoreAdapter",
      "createMemoryKeyStore",
      "createMemoryOperationStoreAdapter",
    ]);
  });

  it("exposes only the EIP-1193 adapter on /viem", () => {
    expect(Object.keys(viem).sort()).toEqual(["oaathProvider"]);
  });

  it("keeps every surface disjoint", () => {
    const surfaces = [root, kernel, advanced, persistence, testing, viem].map((entry) =>
      Object.keys(entry),
    );
    const all = surfaces.flat();
    expect(new Set(all).size).toBe(all.length);
  });
});
