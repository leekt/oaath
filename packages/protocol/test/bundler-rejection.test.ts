import { describe, expect, it } from "vitest";
import {
  captureBundlerRejection,
  OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES,
  readRpcBundlerRejection,
} from "../src/index.js";

describe("closed pre-acceptance rejection evidence", () => {
  it.each([-32500, -32501, -32502, -32503, -32504, -32505, -32506, -32507, -32521])(
    "captures structured code %s",
    (code) => {
      expect(OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES).toContain(code);
      expect(captureBundlerRejection({ code })).toEqual({ code });
      expect(
        readRpcBundlerRejection(
          Object.assign(new Error("private"), { code: "oaath_rpc_rejected", rpcCode: code }),
        ),
      ).toEqual({ code });
    },
  );
  it.each([
    null,
    { code: -32603 },
    { code: -32000 },
    { code: "-32500" },
    { code: -32500, message: "private" },
  ])("refuses ambiguous or expanded evidence", (value) => {
    expect(captureBundlerRejection(value)).toBeNull();
  });
  it("does not infer a rejection from HTTP failures, raw RPC objects, prose, or accessors", () => {
    let reads = 0;
    for (const value of [
      new Error("-32500"),
      { code: -32500 },
      { code: "oaath_rpc_unavailable", rpcCode: -32500 },
      Object.create({ code: "oaath_rpc_rejected", rpcCode: -32500 }),
      Object.defineProperty({ code: "oaath_rpc_rejected" }, "rpcCode", {
        get() {
          reads++;
          return -32500;
        },
      }),
    ])
      expect(readRpcBundlerRejection(value)).toBeNull();
    expect(reads).toBe(0);
  });
});
