import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { hashCanonicalEip712TypedData } from "../src/index.js";

interface Eip712HashMutation {
  readonly name: string;
  readonly pointer: string;
  readonly value: unknown;
  readonly expectedDigest: `0x${string}`;
}

interface Eip712HashVector {
  readonly name: string;
  readonly typedData: unknown;
  readonly expectedDigest: `0x${string}`;
  readonly mutations: readonly Eip712HashMutation[];
}

interface Eip712HashFixture {
  readonly version: string;
  readonly canonicalValueRules: Readonly<Record<string, string>>;
  readonly vectors: readonly Eip712HashVector[];
}

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/eip712-hash-vectors.json", import.meta.url), "utf8"),
) as Eip712HashFixture;

function pointerSegments(pointer: string): readonly string[] {
  if (!pointer.startsWith("/") || pointer === "/") throw new Error("invalid fixture pointer");
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"));
}

function childAt(value: unknown, segment: string): unknown {
  if (Array.isArray(value)) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(segment)) throw new Error("invalid array pointer");
    const index = Number(segment);
    if (index >= value.length) throw new Error("fixture pointer is out of bounds");
    return value[index];
  }
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, segment)) {
    throw new Error("fixture pointer does not exist");
  }
  return (value as Record<string, unknown>)[segment];
}

function applyMutation(typedData: unknown, mutation: Eip712HashMutation): unknown {
  const result = structuredClone(typedData);
  const segments = pointerSegments(mutation.pointer);
  let target = result;
  for (const segment of segments.slice(0, -1)) target = childAt(target, segment);
  const leaf = segments.at(-1);
  if (leaf === undefined) throw new Error("fixture mutation is missing a leaf");

  if (Array.isArray(target)) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(leaf)) throw new Error("invalid array pointer");
    const index = Number(leaf);
    if (index >= target.length) throw new Error("fixture pointer is out of bounds");
    target[index] = mutation.value;
  } else if (typeof target === "object" && target !== null && Object.hasOwn(target, leaf)) {
    (target as Record<string, unknown>)[leaf] = mutation.value;
  } else {
    throw new Error("fixture mutation leaf does not exist");
  }
  return result;
}

describe("shared EIP-712 hash vectors", () => {
  it("declares the current canonical cross-implementation fixture schema", () => {
    expect(fixture).toMatchObject({
      version: "oaath.eip712-hash-vectors/v1",
      canonicalValueRules: {
        integer: "decimal-string",
        hex: "lowercase-0x-even-length",
        boolean: "json-boolean",
        domain: "explicit-EIP712Domain",
      },
    });
    expect(fixture.vectors.map((vector) => vector.name)).toEqual([
      "official-eip712-mail",
      "nested-fixed-and-dynamic-arrays",
      "chainless-dynamic-document",
    ]);
  });

  for (const vector of fixture.vectors) {
    it(`${vector.name} matches its viem digest`, () => {
      expect(hashCanonicalEip712TypedData(vector.typedData)).toBe(vector.expectedDigest);
    });

    for (const mutation of vector.mutations) {
      it(`${vector.name}/${mutation.name} changes one field and matches its viem digest`, () => {
        const baseDigest = hashCanonicalEip712TypedData(vector.typedData);
        const mutatedDigest = hashCanonicalEip712TypedData(
          applyMutation(vector.typedData, mutation),
        );
        expect(baseDigest).toBe(vector.expectedDigest);
        expect(mutatedDigest).toBe(mutation.expectedDigest);
        expect(mutatedDigest).not.toBe(baseDigest);
      });
    }
  }
});
