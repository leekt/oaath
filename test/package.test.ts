import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";

describe("package bootstrap", () => {
  it("exports only accepted Operation owners", () => {
    expect(Object.keys(ogp).sort()).toEqual([
      "OGP_OPERATION_RECORD_VERSION",
      "OgpOperationError",
      "advanceOperation",
      "createOperation",
      "operationOccupiesLane",
      "parseOperation",
    ]);
  });
});
