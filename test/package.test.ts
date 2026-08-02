import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";

describe("package boundary", () => {
  it("exports only accepted Grant and Operation owners", () => {
    expect(Object.keys(ogp).sort()).toEqual([
      "OGP_GRANT_RECORD_VERSION",
      "OGP_OPERATION_RECORD_VERSION",
      "OgpGrantError",
      "OgpOperationError",
      "advanceGrant",
      "advanceOperation",
      "createGrant",
      "createOperation",
      "operationOccupiesLane",
      "parseGrant",
      "parseOperation",
    ]);
  });
});
