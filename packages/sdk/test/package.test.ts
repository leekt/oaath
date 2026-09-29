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
    expect(Object.keys(root).sort()).toEqual([
      "OAATH_CALLS_REVIEW_VERSION",
      "OaathClientError",
      "createOAAth",
      "parseOaathCallsReview",
    ]);
  });

  it("names no Kernel version on the root or /kernel entry", () => {
    // Kernel and EntryPoint versions are optional settings of these entries,
    // never part of a function or constant name. Version-named encoders and
    // constants live on /advanced; the type-level check is check:public-surface.
    const versioned = [...Object.keys(root), ...Object.keys(kernel)].filter((name) =>
      /V33|V4/u.test(name),
    );
    expect(versioned).toEqual([]);
  });

  it("exposes the version-agnostic Kernel primitives on /kernel", () => {
    expect(Object.keys(kernel).sort()).toEqual([
      "OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION",
      "OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION",
      "OAATH_KERNEL_PERMISSION_REVOCATION_VERSION",
      "OAATH_KERNEL_RATE_LIMIT_POLICY",
      "OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH",
      "OAATH_PREPARED_USER_OPERATION_VERSION",
      "OaathKernelRuntimeError",
      "OaathPreparedUserOperationError",
      "approveKernelPermission",
      "asViemUserOperation",
      "bindKernelAccount",
      "compileKernelPermissionPolicy",
      "createKernelReads",
      "createKernelRuntime",
      "deriveOperationId",
      "diagnoseKernelCapability",
      "kernelAccountDeployment",
      "kernelDeployment",
      "kernelKey",
      "kernelPermissionCapabilityHash",
      "kernelPermissionEnableTypedData",
      "kernelPermissionNonce",
      "materializeKernelPermission",
      "ownerOperator",
      "parseKernelPermissionApproval",
      "parsePreparedUserOperation",
      "pinnedPolicyModule",
      "pinnedSignerModule",
      "prepareKernelPermissionRevocation",
      "prepareKernelPhonePermissionApproval",
      "prepareKernelPhoneRevocation",
      "prepareKernelUserOperation",
      "prepareUserOperation",
      "restoreKernelPermissionRevocation",
      "restoreKernelPhoneRevocation",
      "sessionOperator",
      "verifyKernelPermissionApproval",
      "verifyKernelPermissionRevocation",
    ]);
  });

  it("exposes custom-deployment ports on /advanced", () => {
    expect(Object.keys(advanced).sort()).toEqual([
      "ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN",
      "ERC7902_STATIC_PAYMASTER_LIMITS",
      "GrantStore",
      "KERNEL_V4_CREATE2_DEPLOYER",
      "KERNEL_V4_ENTRY_POINT_V07",
      "KERNEL_V4_ENTRY_POINT_V07_CODE_HASH",
      "KERNEL_V4_FACTORY_V07",
      "KERNEL_V4_FACTORY_V07_CODE_HASH",
      "KERNEL_V4_UUPS_IMPLEMENTATION_V07",
      "OAATH_BINDING_HASH_DOMAIN",
      "OAATH_BINDING_VERSION",
      "OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES",
      "OAATH_GRANT_STORE_RECORD_VERSION",
      "OAATH_HANDLE_OPS_OVERHEAD_GAS",
      "OAATH_KERNEL_V33_APPROVAL_VERSION",
      "OAATH_KERNEL_V4_VALIDITY_POLICY",
      "OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH",
      "OAATH_KERNEL_VALIDITY_POLICY",
      "OAATH_KERNEL_VALIDITY_POLICY_RUNTIME_CODE_HASH",
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
      "createUserOperationObserver",
      "decideExecution",
      "deriveHandleOpsRequirement",
      "deriveOperationPrefund",
      "deriveSessionPolicyProfiles",
      "encodeHandleOps",
      "encodeKernelFactoryImplementationRead",
      "encodeKernelInstallNonceInvalidationCall",
      "encodeKernelInstallNonceRead",
      "encodeKernelNonceKey",
      "encodeKernelNonceRead",
      "encodeKernelV33NonceKey",
      "encodeKernelV4FactoryImplementationRead",
      "encodeKernelV4InstallNonceInvalidationCall",
      "encodeKernelV4InstallNonceRead",
      "encodeKernelV4NonceKey",
      "encodeKernelV4NonceRead",
      "forgetLocalEffect",
      "hashErc7902StaticPaymasterConfiguration",
      "kernelOperationSigningHash",
      "kernelReplayableInstallDigest",
      "kernelV33EffectivePermissionNonce",
      "kernelV33OperationSigningHash",
      "kernelV33PermissionEnableTypedData",
      "kernelV33PermissionRevocationCalls",
      "kernelV33PermissionStatus",
      "kernelV4ReplayableInstallDigest",
      "parseKernelV33PermissionState",
      "prepareSponsoredKernelOperation",
      "probeBundlerCapability",
      "readKernelV33PermissionState",
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
      "OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION",
      "OAATH_WALLET_CALL_BUNDLE_VERSION",
      "OaathPersistenceError",
      "createIndexedDbCleanupStore",
      "createIndexedDbContextStore",
      "createIndexedDbGrantStoreAdapter",
      "createIndexedDbKeyStore",
      "createIndexedDbOperationStoreAdapter",
      "createIndexedDbPreparedCallStoreAdapter",
      "createIndexedDbWalletCallBundleStoreAdapter",
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
      "createMemoryPreparedCallStoreAdapter",
      "createMemoryWalletCallBundleStoreAdapter",
    ]);
  });

  it("exposes the provider and default chain ports on /viem", () => {
    expect(Object.keys(viem).sort()).toEqual([
      "OaathRpcError",
      "createViemChainPorts",
      "oaathProvider",
    ]);
  });

  it("keeps every surface disjoint", () => {
    const surfaces = [root, kernel, advanced, persistence, testing, viem].map((entry) =>
      Object.keys(entry),
    );
    const all = surfaces.flat();
    expect(new Set(all).size).toBe(all.length);
  });
});
