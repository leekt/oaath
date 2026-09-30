/**
 * The five published surfaces, pinned name for name. The root entry teaches
 * exactly one product path; everything infrastructural is an explicit subpath
 * a consumer must opt into.
 *
 * @author taek <leekt216@gmail.com>
 */
import { IDBFactory } from "fake-indexeddb";
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

  it("names no Kernel version on any entry", () => {
    // Kernel and EntryPoint versions are detected or optional settings, never
    // part of a function or constant name, /advanced included. The type-level
    // check is check:public-surface.
    const versioned = [root, kernel, advanced, persistence, testing, viem]
      .flatMap((entry) => Object.keys(entry))
      .filter((name) => /V33|V4/u.test(name));
    expect(versioned).toEqual([]);
  });

  it("names no owner signing location on /kernel", () => {
    // Where the owner key lives is expressed by who signs, never by a name.
    expect(Object.keys(kernel).filter((name) => /Phone/u.test(name))).toEqual([]);
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
      "kernelRuntimeReadiness",
      "materializeKernelPermission",
      "ownerOperator",
      "parseKernelPermissionApproval",
      "parsePreparedUserOperation",
      "pinnedPolicyModule",
      "pinnedSignerModule",
      "prepareKernelPermissionApproval",
      "prepareKernelPermissionRevocation",
      "prepareKernelUserOperation",
      "prepareRuntimeModuleDeployment",
      "prepareUserOperation",
      "readKernelPermissionStatus",
      "restoreKernelPermissionRevocation",
      "sessionOperator",
      "signedKernelPermissionApproval",
      "verifyKernelPermissionApproval",
      "verifyKernelPermissionRevocation",
    ]);
  });

  it("exposes custom-deployment ports on /advanced", () => {
    expect(Object.keys(advanced).sort()).toEqual([
      "ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN",
      "ERC7902_STATIC_PAYMASTER_LIMITS",
      "GrantStore",
      "OAATH_BINDING_HASH_DOMAIN",
      "OAATH_BINDING_VERSION",
      "OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES",
      "OAATH_GRANT_STORE_RECORD_VERSION",
      "OAATH_HANDLE_OPS_OVERHEAD_GAS",
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
      "forgetLocalEffect",
      "hashErc7902StaticPaymasterConfiguration",
      "kernelOperationSigningHash",
      "kernelReplayableInstallDigest",
      "prepareSponsoredKernelOperation",
      "probeBundlerCapability",
      "revokeEffect",
      "runOaathCleanup",
      "signOutEffect",
    ]);
  });

  it("exposes one IndexedDB store set and record contracts on /persistence", () => {
    expect(Object.keys(persistence).sort()).toEqual([
      "OAATH_CLEANUP_CHECKPOINT_VERSION",
      "OAATH_CLIENT_CONTEXT_VERSION",
      "OAATH_INDEXEDDB_NAME",
      "OAATH_INDEXEDDB_STORES",
      "OAATH_INDEXEDDB_VERSION",
      "OAATH_WALLET_CALL_BUNDLE_STORE_RECORD_VERSION",
      "OAATH_WALLET_CALL_BUNDLE_VERSION",
      "OaathPersistenceError",
      "isCleanupEffectName",
      "openIndexedDbStores",
      "parseCleanupCheckpoint",
      "parseClientContext",
      "requireNonExtractableKey",
    ]);
  });

  it("exposes only the deterministic memory store set on /testing", () => {
    expect(Object.keys(testing).sort()).toEqual(["createMemoryStores"]);
  });

  it("returns every store from each backend factory and fails closed without IndexedDB", async () => {
    const names = [
      "cleanup",
      "context",
      "grants",
      "keys",
      "operations",
      "preparedCallContexts",
      "walletCallBundles",
    ];
    expect(Object.keys(testing.createMemoryStores()).sort()).toEqual(names);
    const indexed = await persistence.openIndexedDbStores({ factory: new IDBFactory() });
    expect(Object.keys(indexed.stores).sort()).toEqual(names);
    await indexed.close();
    await expect(persistence.openIndexedDbStores()).rejects.toMatchObject({
      code: "oaath_client_store_unavailable",
    });
    await expect(
      persistence.openIndexedDbStores({ operations: {} } as never),
    ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });
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
