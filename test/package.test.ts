import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";
import * as testing from "../src/testing.js";

describe("package boundary", () => {
  it("exports only accepted policy, aggregate, Kernel, observer, runner, and store owners", () => {
    expect(Object.keys(ogp).sort()).toEqual([
      "GrantStore",
      "KERNEL_RUNTIME_CAPABILITIES",
      "OGP_GRANT_POLICY_HASH_DOMAIN",
      "OGP_GRANT_POLICY_USAGE_VERSION",
      "OGP_GRANT_POLICY_VERSION",
      "OGP_GRANT_RECORD_VERSION",
      "OGP_GRANT_STORE_RECORD_VERSION",
      "OGP_KERNEL_ACCOUNT_PROFILE_VERSION",
      "OGP_KERNEL_RUNTIME_CAPABILITIES_VERSION",
      "OGP_OPERATION_RECORD_VERSION",
      "OGP_OPERATION_STORE_RECORD_VERSION",
      "OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION",
      "OGP_OWNER_CREDENTIAL_PROFILE_VERSION",
      "OGP_PREPARED_USER_OPERATION_VERSION",
      "OgpGrantError",
      "OgpGrantPolicyError",
      "OgpIdentityProfileError",
      "OgpKernelHandleOpsAdapterError",
      "OgpKernelPermissionObserverError",
      "OgpKernelPermissionRevocationError",
      "OgpKernelRuntimeCapabilitiesError",
      "OgpOperationError",
      "OgpOperationObserverError",
      "OgpOperationRunnerError",
      "OgpPreparedUserOperationError",
      "OgpStoreError",
      "OperationStore",
      "advanceGrant",
      "advanceOperation",
      "createGrant",
      "createKernelAccountActionInput",
      "createKernelPermissionRemovalObserver",
      "createKernelPermissionRevocationCoordinator",
      "createLocalKernelHandleOpsAdapter",
      "createLocalKernelPermissionUninstallAdapter",
      "createOperation",
      "createOperationObserver",
      "createOperationRunner",
      "deriveOperationId",
      "diagnoseOperatorCredential",
      "diagnoseOwnerCredential",
      "encodeGrantPolicy",
      "evaluateGrantPolicyCoverage",
      "getKernelRuntimeCapability",
      "hashGrantPolicy",
      "isGrantPolicyAttenuation",
      "operationOccupiesLane",
      "parseGrant",
      "parseGrantPolicy",
      "parseKernelAccountProfile",
      "parseOperation",
      "parseOperatorCredentialProfile",
      "parseOwnerCredentialProfile",
      "parsePreparedUserOperation",
      "prepareUserOperation",
    ]);
  });

  it("keeps the concrete SQLite stores on the testing subpath", () => {
    expect(Object.keys(testing).sort()).toEqual([
      "createSqliteGrantStore",
      "createSqliteOperationStore",
    ]);
  });
});
