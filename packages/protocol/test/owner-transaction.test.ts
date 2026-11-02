import { describe, expect, it } from "vitest";
import {
  hashOwnerTransactionRequest,
  OAATH_OWNER_TRANSACTION_REQUEST_VERSION,
  parseOwnerTransactionRequest,
} from "../src/index.js";

const FROM = `0x${"11".repeat(20)}` as const;
const request = {
  version: OAATH_OWNER_TRANSACTION_REQUEST_VERSION,
  chainId: 8453,
  from: FROM,
  to: `0x${"22".repeat(20)}`,
  value: "1000000000000000000",
  data: "0xabcdef01",
};

describe("owner transaction requests", () => {
  it("captures a value-bearing call and a contract creation, each with a stable identity", () => {
    expect(parseOwnerTransactionRequest(request)).toEqual(request);
    const creation = { ...request, to: null, value: "0", data: "0x6080" };
    expect(parseOwnerTransactionRequest(creation)).toEqual(creation);
    const hash = hashOwnerTransactionRequest(request);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(hashOwnerTransactionRequest({ ...request })).toBe(hash);
    // Every field is bound: chain, sender, target or creation, value and data.
    for (const other of [
      { ...request, chainId: 1 },
      { ...request, from: `0x${"33".repeat(20)}` },
      { ...request, to: `0x${"44".repeat(20)}` },
      { ...request, value: "1" },
      { ...request, data: "0xabcdef02" },
    ])
      expect(hashOwnerTransactionRequest(other)).not.toBe(hash);
  });

  it("refuses anything inexact", () => {
    for (const value of [
      { ...request, version: "oaath.owner-transaction-request/v2" },
      { ...request, chainId: 0 },
      { ...request, from: "0x0000000000000000000000000000000000000000" },
      { ...request, value: "01" },
      { ...request, value: "-1" },
      { ...request, data: "0xABCD" },
      { ...request, data: "0x123" },
      { ...request, to: null, data: "0x" },
      // A creation is `to: null`, never the zero address.
      { ...request, to: "0x0000000000000000000000000000000000000000" },
      { ...request, extra: 1 },
    ])
      expect(() => parseOwnerTransactionRequest(value)).toThrow(
        expect.objectContaining({ code: "signing_request_invalid" }),
      );
  });
});
