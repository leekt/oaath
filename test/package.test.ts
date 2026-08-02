import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";
import * as testing from "../src/testing.js";

describe("package boundary", () => {
  it("exports only accepted aggregate, prepared identity, and store owners", () => {
    expect(Object.keys(ogp).sort()).toEqual([
      "GrantStore",
      "OGP_GRANT_RECORD_VERSION",
      "OGP_GRANT_STORE_RECORD_VERSION",
      "OGP_OPERATION_RECORD_VERSION",
      "OGP_OPERATION_STORE_RECORD_VERSION",
      "OGP_PREPARED_USER_OPERATION_VERSION",
      "OgpGrantError",
      "OgpOperationError",
      "OgpOperationObserverError",
      "OgpPreparedUserOperationError",
      "OgpStoreError",
      "OperationStore",
      "advanceGrant",
      "advanceOperation",
      "createGrant",
      "createOperation",
      "createOperationObserver",
      "deriveOperationId",
      "operationOccupiesLane",
      "parseGrant",
      "parseOperation",
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
