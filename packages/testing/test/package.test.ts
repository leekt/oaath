import { describe, expect, it } from "vitest";
import * as testing from "../src/index.js";

describe("package boundary", () => {
  it("exports only the concrete SQLite test stores", () => {
    expect(Object.keys(testing).sort()).toEqual([
      "createSqliteGrantStore",
      "createSqliteOperationStore",
    ]);
  });
});
