import { describe, expect, it } from "vitest";
import * as ogp from "../src/index.js";

describe("package bootstrap", () => {
  it("exports no speculative product API", () => {
    expect(Object.keys(ogp)).toEqual([]);
  });
});
