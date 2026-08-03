import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";
import * as testing from "../src/testing.js";

describe("package boundary", () => {
  it("exports only accepted aggregate, Kernel operation, observer, runner, and store owners", () => {
    expect(Object.keys(ogp).sort()).toEqual([
      "GrantStore",
      "KERNEL_V4_CREATE2_DEPLOYER",
      "KERNEL_V4_ENTRY_POINT_V07",
      "KERNEL_V4_ENTRY_POINT_V07_CODE_HASH",
      "KERNEL_V4_FACTORY_V07",
      "KERNEL_V4_FACTORY_V07_CODE_HASH",
      "KERNEL_V4_UUPS_IMPLEMENTATION_V07",
      "OGP_GRANT_RECORD_VERSION",
      "OGP_GRANT_STORE_RECORD_VERSION",
      "OGP_OPERATION_RECORD_VERSION",
      "OGP_OPERATION_STORE_RECORD_VERSION",
      "OGP_PREPARED_USER_OPERATION_VERSION",
      "OgpGrantError",
      "OgpKernelV4Error",
      "OgpOperationError",
      "OgpOperationObserverError",
      "OgpOperationRunnerError",
      "OgpPreparedUserOperationError",
      "OgpStoreError",
      "OperationStore",
      "advanceGrant",
      "advanceOperation",
      "bindKernelV4Account",
      "createGrant",
      "createOperation",
      "createOperationObserver",
      "createOperationRunner",
      "deriveOperationId",
      "encodeKernelV4EnableSignature",
      "encodeKernelV4Execution",
      "encodeKernelV4FactoryAddressRead",
      "encodeKernelV4FactoryDeploy",
      "encodeKernelV4FactoryImplementationRead",
      "encodeKernelV4Initialize",
      "encodeKernelV4InstallModules",
      "encodeKernelV4Nonce",
      "encodeKernelV4NonceKey",
      "encodeKernelV4PermissionSignature",
      "encodeKernelV4PolicyData",
      "encodeKernelV4SignerData",
      "encodeKernelV4ValidatorData",
      "kernelV4Deployment",
      "operationOccupiesLane",
      "parseGrant",
      "parseOperation",
      "parsePreparedUserOperation",
      "prepareKernelV4UserOperation",
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
