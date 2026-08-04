const HASH = /^0x[0-9a-f]{64}$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;

export const OPERATION_FINALITY_MAX_ANCESTRY_DEPTH = 64;

export interface FinalityBlockReference {
  readonly number: `0x${string}`;
  readonly hash: `0x${string}`;
  readonly parentHash: `0x${string}`;
}

export interface VerifyFinalizedBlockAncestryInput {
  readonly finalized: unknown;
  readonly inclusion: Readonly<{ number: unknown; hash: unknown }>;
  readonly maxDepth: number;
  readonly readParent: (blockHash: `0x${string}`) => Promise<unknown>;
  readonly readCanonical: (blockNumber: string) => Promise<unknown>;
}

export class OaathFinalityAncestryError extends Error {
  constructor() {
    super("operation_finality_ancestry_unproven");
    this.name = "OaathFinalityAncestryError";
  }
}

function fail(): never {
  throw new OaathFinalityAncestryError();
}

function block(value: unknown): FinalityBlockReference {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return fail();
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== "hash,number,parentHash" ||
    typeof record.number !== "string" ||
    !QUANTITY.test(record.number) ||
    typeof record.hash !== "string" ||
    !HASH.test(record.hash) ||
    typeof record.parentHash !== "string" ||
    !HASH.test(record.parentHash)
  )
    return fail();
  return Object.freeze({
    number: record.number as `0x${string}`,
    hash: record.hash as `0x${string}`,
    parentHash: record.parentHash as `0x${string}`,
  });
}

/**
 * Proves that a finalized head descends from an inclusion block, then rebounds
 * both endpoints through canonical number reads. The caller supplies an
 * explicit parent-read budget; exhaustion is unresolved evidence, never
 * finality.
 */
export async function verifyFinalizedBlockAncestry(
  input: VerifyFinalizedBlockAncestryInput,
): Promise<FinalityBlockReference> {
  if (
    !Number.isSafeInteger(input.maxDepth) ||
    input.maxDepth < 0 ||
    input.maxDepth > OPERATION_FINALITY_MAX_ANCESTRY_DEPTH ||
    typeof input.readParent !== "function" ||
    typeof input.readCanonical !== "function"
  )
    return fail();
  const finalized = block(input.finalized);
  const inclusion = block({
    number: input.inclusion.number,
    hash: input.inclusion.hash,
    parentHash: `0x${"00".repeat(32)}`,
  });
  const finalizedNumber = BigInt(finalized.number);
  const inclusionNumber = BigInt(inclusion.number);
  if (finalizedNumber < inclusionNumber || finalizedNumber - inclusionNumber > input.maxDepth)
    return fail();

  let descendant = finalized;
  let descendantNumber = finalizedNumber;
  while (descendantNumber > inclusionNumber) {
    const parent = block(await input.readParent(descendant.parentHash));
    const parentNumber = BigInt(parent.number);
    if (parent.hash !== descendant.parentHash || parentNumber + 1n !== descendantNumber)
      return fail();
    descendant = parent;
    descendantNumber = parentNumber;
  }
  if (descendant.hash !== inclusion.hash) return fail();

  const [reboundFinalized, reboundInclusion] = await Promise.all([
    input.readCanonical(finalizedNumber.toString(10)).then(block),
    input.readCanonical(inclusionNumber.toString(10)).then(block),
  ]);
  if (
    reboundFinalized.number !== finalized.number ||
    reboundFinalized.hash !== finalized.hash ||
    reboundInclusion.number !== inclusion.number ||
    reboundInclusion.hash !== inclusion.hash
  )
    return fail();
  return finalized;
}
