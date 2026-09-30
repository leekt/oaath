/** Provider failure decoding belongs here, never in routing or retry decisions. */
import { decodeErrorResult, encodeErrorResult } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";

const STAGES = ["estimate", "sponsor", "send", "receipt"] as const;
export type UserOperationFailureStage = (typeof STAGES)[number];
const FAILURE_CODES = [
  "invalid-signature",
  "insufficient-funds",
  "nonce",
  "paymaster-policy",
  "account-validation",
  "paymaster-validation",
  "deployment",
  "expired",
  "gas",
  "invalid-request",
  "transport",
  "rate-limited",
  "unknown",
] as const;
export type UserOperationFailureCode = (typeof FAILURE_CODES)[number];
const minted = new WeakSet<object>();

// EntryPoint 0.7's FailedOp/FailedOpWithRevert reasons. AA23/AA33 alone do not
// distinguish signature/policy rejection from arbitrary validation reverts.
const ENTRY_POINT_CODES = {
  AA10: "deployment",
  AA13: "deployment",
  AA14: "deployment",
  AA15: "deployment",
  AA20: "deployment",
  AA21: "insufficient-funds",
  AA22: "expired",
  AA23: "account-validation",
  AA24: "invalid-signature",
  AA25: "nonce",
  AA26: "gas",
  AA30: "deployment",
  AA31: "insufficient-funds",
  AA32: "expired",
  AA33: "paymaster-validation",
  AA34: "invalid-signature",
  AA36: "gas",
  AA40: "gas",
  AA41: "gas",
  AA50: "paymaster-validation",
  AA51: "insufficient-funds",
  AA90: "invalid-request",
  AA91: "invalid-request",
  AA92: "invalid-request",
  AA93: "invalid-request",
  AA94: "gas",
  AA95: "gas",
  AA96: "invalid-request",
} as const satisfies Record<string, UserOperationFailureCode>;
export type EntryPointFailureCode = keyof typeof ENTRY_POINT_CODES;

/** Ephemeral diagnostics only. Never grants fallback, lane release, or resubmission. */
export class OaathUserOperationError extends Error {
  readonly retryable: boolean;
  constructor(
    readonly stage: UserOperationFailureStage,
    readonly code: UserOperationFailureCode,
    cause: unknown,
    readonly entryPointCode?: EntryPointFailureCode,
  ) {
    if (
      !STAGES.includes(stage) ||
      !FAILURE_CODES.includes(code) ||
      (entryPointCode !== undefined && !Object.hasOwn(ENTRY_POINT_CODES, entryPointCode))
    )
      throw new TypeError("Invalid UserOperation failure classification");
    super(`UserOperation ${stage} failed: ${code}`, { cause });
    minted.add(this);
    this.name = "OaathUserOperationError";
    // Only read-only work is positively safe to repeat. In particular, sponsor
    // services may consume quotas and a missing send response proves nothing.
    this.retryable =
      (stage === "estimate" || stage === "receipt") &&
      (code === "transport" || code === "rate-limited");
    Object.freeze(this);
  }
}

function own(value: unknown, key: string): unknown {
  if (value === null || typeof value !== "object") return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && "value" in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

/** Only follows bounded error/cause/data/body links, never a request or its parameters. */
function nodes(error: unknown): unknown[] {
  const queue: unknown[] = [error];
  const seen = new Set<unknown>();
  const result: unknown[] = [];
  while (queue.length && result.length < 32) {
    const value = queue.shift();
    if (value === undefined || value === null || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
    if (typeof value === "string" && value.length <= 65536 && value.trimStart().startsWith("{")) {
      try {
        queue.push(JSON.parse(value));
      } catch {
        /* Not a JSON error body. */
      }
    } else if (typeof value === "object") {
      for (const key of ["cause", "error", "data", "body"]) queue.push(own(value, key));
    }
  }
  return result;
}

/** Reads only errors minted here; a caller's lookalike never supplies diagnostic facts. */
export function readUserOperationFailure(error: unknown): Readonly<OaathUserOperationError> | null {
  for (const value of nodes(error)) {
    if (value !== null && typeof value === "object" && minted.has(value))
      return value as OaathUserOperationError;
    const failure = own(value, "failure");
    if (failure !== null && typeof failure === "object" && minted.has(failure))
      return failure as OaathUserOperationError;
  }
  return null;
}

/**
 * Normalizes RPC/viem/caller-adapter errors. ERC-7769 numeric codes and exact
 * EntryPoint ABI errors are preferred; standard AA tokens are captured at this
 * boundary only. Unrecognized/contradictory evidence is unknown. The original
 * cause remains available but is non-enumerable and must not be logged.
 */
export function classifyUserOperationError(
  input: Readonly<{
    stage: UserOperationFailureStage;
    error: unknown;
  }>,
): Readonly<OaathUserOperationError> {
  const { stage, error } = input;
  if (!STAGES.includes(stage)) throw new TypeError("Invalid UserOperation failure stage");
  const prior = readUserOperationFailure(error);
  if (prior && prior.stage === stage) return prior;
  if (prior) return new OaathUserOperationError(stage, prior.code, error, prior.entryPointCode);
  const values = nodes(error);
  const entryPoints = new Set<string>();
  const rpcCodes = new Set<number>();
  let transport = false,
    rateLimited = false,
    policy = false;
  function aa(text: unknown) {
    if (typeof text !== "string" || text.length > 65536) return;
    for (const match of text.matchAll(/\bAA[0-9]{2}\b/gu)) entryPoints.add(match[0]);
  }
  for (const value of values) {
    const code = own(value, "rpcCode") ?? own(value, "code");
    if (typeof code === "number") rpcCodes.add(code);
    if (code === "oaath_rpc_unavailable") transport = true;
    const name = own(value, "name");
    if (name === "HttpRequestError" || name === "TimeoutError" || name === "WebSocketRequestError")
      transport = true;
    const status = own(value, "status");
    if (status === 429) rateLimited = true;
    if (typeof status === "number" && status >= 500 && status <= 599) transport = true;
    for (const key of ["message", "shortMessage", "details"]) {
      const text = own(value, key);
      aa(text);
      if (
        stage === "sponsor" &&
        typeof text === "string" &&
        text.length <= 65536 &&
        /\b(?:sponsorship policy (?:denied|rejected)|not (?:allowlisted|whitelisted)|policy (?:rejected|denied)|gas sponsorship denied)\b/iu.test(
          text,
        )
      )
        policy = true;
    }
    if (typeof value === "string" && /^0x[0-9a-f]+$/iu.test(value) && value.length <= 65536) {
      try {
        const decoded = decodeErrorResult({ abi: entryPoint07Abi, data: value as `0x${string}` });
        if (
          (decoded.errorName === "FailedOp" || decoded.errorName === "FailedOpWithRevert") &&
          encodeErrorResult({
            abi: entryPoint07Abi,
            errorName: decoded.errorName,
            args: decoded.args,
          }).toLowerCase() === value.toLowerCase()
        )
          aa(decoded.args[1]);
      } catch {
        /* Unknown ABI bytes confer no classification. */
      }
    }
  }
  let code: UserOperationFailureCode = "unknown";
  let entryPointCode: EntryPointFailureCode | undefined;
  const token = [...entryPoints][0];
  if (entryPoints.size > 1) return new OaathUserOperationError(stage, code, error);
  if (token && Object.hasOwn(ENTRY_POINT_CODES, token)) {
    entryPointCode = token as EntryPointFailureCode;
    code = ENTRY_POINT_CODES[entryPointCode];
  } else if (token) code = "unknown";
  else if (rpcCodes.has(-32507)) code = "invalid-signature";
  else if (rpcCodes.has(-32508)) code = "insufficient-funds";
  else if (rpcCodes.has(-32501) || rpcCodes.has(-32504) || rpcCodes.has(-32505) || policy)
    code = "paymaster-policy";
  else if (rpcCodes.has(-32503)) code = "expired";
  else if (rpcCodes.has(-32602) || rpcCodes.has(-32502)) code = "invalid-request";
  else if (rateLimited || [-32005, -32016, 429].some((value) => rpcCodes.has(value)))
    code = "rate-limited";
  else if (transport) code = "transport";
  return new OaathUserOperationError(stage, code, error, entryPointCode);
}

/** Versioned relay diagnostics; contains no provider text, request, or original cause. */
export interface UserOperationFailure {
  readonly version: "oaath.user-operation-failure/v1";
  readonly stage: UserOperationFailureStage;
  readonly code: UserOperationFailureCode;
  readonly entryPointCode?: EntryPointFailureCode;
  readonly retryable: boolean;
}

/** Serializes only classifications minted by this owner, including wrapped causes. */
export function serializeUserOperationFailure(
  error: unknown,
): Readonly<UserOperationFailure> | null {
  const failure = readUserOperationFailure(error);
  if (!failure) return null;
  return Object.freeze({
    version: "oaath.user-operation-failure/v1",
    stage: failure.stage,
    code: failure.code,
    ...(failure.entryPointCode === undefined ? {} : { entryPointCode: failure.entryPointCode }),
    retryable: failure.retryable,
  });
}

/** Exact wire capture. Reconstructs diagnostics only; the remote cause stays remote. */
export function parseUserOperationFailure(
  value: unknown,
): Readonly<OaathUserOperationError> | null {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const allowed = ["version", "stage", "code", "entryPointCode", "retryable"];
    if (Reflect.ownKeys(value).some((key) => typeof key !== "string" || !allowed.includes(key)))
      return null;
    const version = own(value, "version");
    const stage = own(value, "stage") as UserOperationFailureStage;
    const code = own(value, "code") as UserOperationFailureCode;
    const entryPointCode = own(value, "entryPointCode") as EntryPointFailureCode | undefined;
    if (
      version !== "oaath.user-operation-failure/v1" ||
      !STAGES.includes(stage) ||
      !FAILURE_CODES.includes(code)
    )
      return null;
    if (
      Object.hasOwn(value, "entryPointCode") &&
      (entryPointCode === undefined ||
        !Object.hasOwn(ENTRY_POINT_CODES, entryPointCode) ||
        ENTRY_POINT_CODES[entryPointCode] !== code)
    )
      return null;
    const captured = new OaathUserOperationError(stage, code, undefined, entryPointCode);
    return own(value, "retryable") === captured.retryable ? captured : null;
  } catch {
    return null;
  }
}
