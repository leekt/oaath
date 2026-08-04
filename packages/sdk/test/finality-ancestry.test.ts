import { describe, expect, it } from "vitest";
import {
  OaathFinalityAncestryError,
  verifyFinalizedBlockAncestry,
} from "../src/finality-ancestry.js";

const hash = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;

describe("verifyFinalizedBlockAncestry", () => {
  it("proves parent ancestry and rebounds both canonical endpoints", async () => {
    const inclusion = { number: "0x7", hash: hash("1"), parentHash: hash("0") };
    const parent = { number: "0x8", hash: hash("2"), parentHash: inclusion.hash };
    const finalized = { number: "0x9", hash: hash("3"), parentHash: parent.hash };
    const byHash = new Map([
      [parent.hash, parent],
      [inclusion.hash, inclusion],
    ]);
    const canonical = new Map([
      ["7", inclusion],
      ["9", finalized],
    ]);
    const result = await verifyFinalizedBlockAncestry({
      finalized,
      inclusion,
      maxDepth: 2,
      readParent: async (blockHash) => byHash.get(blockHash),
      readCanonical: async (blockNumber) => canonical.get(blockNumber),
    });
    expect(result).toEqual(finalized);
  });

  it("rejects unrelated ancestry and canonical endpoint rebound", async () => {
    const inclusion = { number: "0x7", hash: hash("1"), parentHash: hash("0") };
    const unrelated = { number: "0x7", hash: hash("4"), parentHash: hash("0") };
    const finalized = { number: "0x8", hash: hash("3"), parentHash: unrelated.hash };
    await expect(
      verifyFinalizedBlockAncestry({
        finalized,
        inclusion,
        maxDepth: 1,
        readParent: async () => unrelated,
        readCanonical: async () => finalized,
      }),
    ).rejects.toBeInstanceOf(OaathFinalityAncestryError);

    await expect(
      verifyFinalizedBlockAncestry({
        finalized: { ...finalized, parentHash: inclusion.hash },
        inclusion,
        maxDepth: 1,
        readParent: async () => inclusion,
        readCanonical: async (number) =>
          number === "7" ? { ...inclusion, hash: hash("5") } : finalized,
      }),
    ).rejects.toBeInstanceOf(OaathFinalityAncestryError);
  });

  it("fails before parent reads when the explicit ancestry budget is exceeded", async () => {
    let reads = 0;
    await expect(
      verifyFinalizedBlockAncestry({
        finalized: { number: "0x10", hash: hash("3"), parentHash: hash("2") },
        inclusion: { number: "0x7", hash: hash("1") },
        maxDepth: 8,
        readParent: async () => {
          reads += 1;
          return null;
        },
        readCanonical: async () => null,
      }),
    ).rejects.toBeInstanceOf(OaathFinalityAncestryError);
    expect(reads).toBe(0);
  });
});
