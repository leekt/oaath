import {
  captureDenseArray,
  captureRecord,
  captureValidationGasDiagnostic,
  classifyUserOperationError,
  entryPointAbi,
  type OaathUserOperationError,
  type UserOperationFailureStage,
  type ValidationGasDiagnostic,
  validationGasDiagnosticMessage,
} from "@oaath/protocol";
import { decodeErrorResult, encodeErrorResult } from "cetane/utils";

export type OaathRpcErrorCode =
  | "oaath_rpc_config_invalid"
  | "oaath_rpc_bundler_unavailable"
  | "oaath_rpc_aborted"
  | "oaath_rpc_unavailable"
  | "oaath_rpc_rejected"
  | "oaath_rpc_wrong_chain"
  | "oaath_rpc_evidence_invalid"
  | "oaath_rpc_budget_exhausted"
  | "oaath_rpc_concurrency_exceeded";

/** Public fields/message are sanitized. Original provider errors remain only in non-enumerable cause. */
export class OaathRpcError extends Error {
  readonly code: OaathRpcErrorCode;
  readonly rpcCode: number | null;
  readonly failure?: Readonly<OaathUserOperationError>;
  readonly diagnostic: Readonly<ValidationGasDiagnostic> | null;
  constructor(
    code: OaathRpcErrorCode,
    rpcCode: number | null = null,
    diagnostic: Readonly<ValidationGasDiagnostic> | null = null,
    options?: ErrorOptions,
  ) {
    const captured = captureValidationGasDiagnostic(diagnostic);
    super(captured === null ? code : validationGasDiagnosticMessage(captured), options);
    this.name = "OaathRpcError";
    this.code = code;
    this.rpcCode = rpcCode;
    this.diagnostic = captured;
  }
}

function validationDiagnostic(
  method: string,
  params: readonly unknown[],
  data: unknown,
): Readonly<ValidationGasDiagnostic> | null {
  if (method !== "eth_estimateUserOperationGas" && method !== "eth_sendUserOperation") return null;
  try {
    if (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})+$/iu.test(data)) return null;
    const decoded = decodeErrorResult({ abi: entryPointAbi, data: data as `0x${string}` });
    if (
      decoded.errorName !== "FailedOpWithRevert" ||
      decoded.args[0] !== 0n ||
      decoded.args[1] !== "AA23 reverted" ||
      decoded.args[2] !== "0x"
    )
      return null;
    return captureValidationGasDiagnostic({
      kind: "validation_gas_likely_insufficient",
      verificationGasLimit: quantity(object(params[0]).verificationGasLimit).toString(),
    });
  } catch {
    return null;
  }
}

// This marker belongs to one captured estimation response. Diagnostic text and
// publicly constructed errors cannot manufacture pre-submission evidence.
const accountValidationRejections = new WeakSet<OaathRpcError>();
export function isAccountValidationRejection(error: unknown): boolean {
  return error instanceof OaathRpcError && accountValidationRejections.has(error);
}

function accountValidationReverted(data: unknown): boolean {
  try {
    if (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})+$/iu.test(data)) return false;
    const decoded = decodeErrorResult({ abi: entryPointAbi, data: data as `0x${string}` });
    // The ABI-encoded EntryPoint error identifies account validation. Arbitrary
    // RPC prose, other operation indices and signature placeholders do not.
    return (
      decoded.errorName === "FailedOpWithRevert" &&
      decoded.args[0] === 0n &&
      decoded.args[1] === "AA23 reverted" &&
      encodeErrorResult({
        abi: entryPointAbi,
        errorName: decoded.errorName,
        args: decoded.args,
      }).toLowerCase() === data.toLowerCase()
    );
  } catch {
    return false;
  }
}

// Marks only a well-formed JSON-RPC error answer to eth_sendUserOperation,
// captured from the wire by this owner. Transport failures, timeouts,
// malformed bodies and caller-created errors never carry it.
const submissionRejections = new WeakSet<OaathRpcError>();
/** True only when the bundler conclusively answered the one send with a JSON-RPC error. */
export function isSubmissionRejection(error: unknown): error is OaathRpcError {
  return error instanceof OaathRpcError && submissionRejections.has(error);
}

const transient = new WeakSet<OaathRpcError>();
function unavailable(cause?: unknown): OaathRpcError {
  const error = new OaathRpcError("oaath_rpc_unavailable", null, null, { cause });
  transient.add(error);
  return error;
}
function copyRpcError(error: OaathRpcError): OaathRpcError {
  const copy = new OaathRpcError(error.code, error.rpcCode, error.diagnostic, {
    cause: error.cause,
  });
  if (error.failure)
    Object.defineProperty(copy, "failure", { value: error.failure, enumerable: true });
  if (accountValidationRejections.has(error)) accountValidationRejections.add(copy);
  if (submissionRejections.has(error)) submissionRejections.add(copy);
  if (transient.has(error)) transient.add(copy);
  return copy;
}
export function invalid(): never {
  throw new OaathRpcError("oaath_rpc_config_invalid");
}
export function evidence(): never {
  throw new OaathRpcError("oaath_rpc_evidence_invalid");
}
export function record(
  value: unknown,
  keys?: readonly string[],
): Readonly<Record<string, unknown>> {
  const result = captureRecord(value, "RPC configuration", new WeakSet(), invalid);
  if (keys && Object.keys(result).some((key) => !keys.includes(key))) invalid();
  return result;
}
export function integer(value: unknown, fallback: number, maximum: number, minimum = 1): number {
  if (value === undefined) return fallback;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    invalid();
  return value;
}
export function url(value: unknown): string {
  if (typeof value !== "string") return invalid();
  try {
    const parsed = new URL(value);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.hash ||
      parsed.username ||
      parsed.password
    )
      invalid();
    return parsed.href;
  } catch {
    return invalid();
  }
}
export function urls(value: unknown): readonly string[] {
  const entries = captureDenseArray(value, "public RPC URLs", new WeakSet(), invalid);
  if (entries.length === 0 || entries.length > 16) invalid();
  return Object.freeze(entries.map(url));
}
export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return evidence();
  return value as Record<string, unknown>;
}
export function quantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/iu.test(value)) return evidence();
  return BigInt(value);
}

export interface CetaneChainPortOptions {
  /** Cancels this instance’s requests and retry waits; cancellation never permits resubmission. */
  readonly signal?: AbortSignal;
  readonly retry?: Readonly<{ attempts: number; delayMs?: number }>;
  readonly timeoutMs?: number;
  /** Hard instance-lifetime budget across every chain, including chain checks and retries. */
  readonly maxRequests?: number;
  /** Bounds wire requests; identical in-flight reads share a slot. Excess requests fail immediately. */
  readonly maxConcurrency?: number;
  readonly fetch?: (request: Request) => Promise<Response>;
}

export type RpcRequest = (
  method: string,
  params?: readonly unknown[],
  retry?: boolean,
) => Promise<unknown>;

// Only side-effect-free reads may share a request. Estimates and sponsorship
// can allocate provider resources, and submission belongs to its own owner.
const COALESCED_READS = new Set([
  "eth_chainId",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_call",
  "eth_gasPrice",
  "eth_maxPriorityFeePerGas",
  "eth_feeHistory",
  "eth_getBlockByNumber",
  "eth_getTransactionByHash",
  "eth_getTransactionReceipt",
  "eth_supportedEntryPoints",
  "eth_getUserOperationReceipt",
]);

/** One budget and concurrency owner shared by all pools in one configuration. */
export function rpcOwner(input: CetaneChainPortOptions) {
  const options = record(input, [
    "retry",
    "timeoutMs",
    "maxRequests",
    "maxConcurrency",
    "fetch",
    "signal",
  ]);
  const retry = options.retry === undefined ? {} : record(options.retry, ["attempts", "delayMs"]);
  const attempts = integer(retry.attempts, 3, 5);
  const delayMs = integer(retry.delayMs, 100, 5_000, 0);
  const timeoutMs = integer(options.timeoutMs, 10_000, 60_000);
  const maxRequests = integer(options.maxRequests, 1_000, 1_000_000);
  const maxConcurrency = integer(options.maxConcurrency, 4, 32);
  if (options.fetch !== undefined && typeof options.fetch !== "function") invalid();
  const fetcher = (options.fetch ?? globalThis.fetch) as (request: Request) => Promise<Response>;
  if (typeof fetcher !== "function") invalid();
  const capturedSignal = options.signal;
  if (capturedSignal !== undefined && !(capturedSignal instanceof AbortSignal)) return invalid();
  const signal: AbortSignal | undefined = capturedSignal;
  const aborted = () =>
    new OaathRpcError("oaath_rpc_aborted", null, null, { cause: signal?.reason });
  async function retryDelay() {
    if (signal?.aborted) throw aborted();
    if (delayMs === 0) return;
    await new Promise<void>((resolve, reject) => {
      const cancel = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", cancel);
        reject(aborted());
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", cancel);
        resolve();
      }, delayMs);
      signal?.addEventListener("abort", cancel, { once: true });
    });
  }
  let used = 0;
  let active = 0;

  async function once(
    endpoint: string,
    method: string,
    params: readonly unknown[],
    headers: Headers,
  ) {
    if (signal?.aborted) throw aborted();
    if (used >= maxRequests) throw new OaathRpcError("oaath_rpc_budget_exhausted");
    if (active >= maxConcurrency) throw new OaathRpcError("oaath_rpc_concurrency_exceeded");
    const id = ++used;
    active += 1;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancel: (() => void) | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await fetcher(
            new Request(endpoint, {
              method: "POST",
              headers,
              body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
              signal: abort.signal,
              redirect: "error",
              credentials: "omit",
            }),
          );
          if (response.status === 429 || response.status >= 500) {
            await response.body?.cancel();
            throw unavailable(response);
          }
          const reader = response.body?.getReader();
          if (!reader) throw unavailable();
          const decoder = new TextDecoder();
          let size = 0;
          let text = "";
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.length;
            if (size > 2 * 1024 * 1024) {
              await reader.cancel();
              throw unavailable();
            }
            text += decoder.decode(chunk.value, { stream: true });
          }
          text += decoder.decode();
          let result: Record<string, unknown>;
          try {
            result = object(JSON.parse(text));
          } catch {
            if (!response.ok)
              throw new OaathRpcError("oaath_rpc_rejected", null, null, { cause: response });
            throw unavailable();
          }
          if (
            result.jsonrpc !== "2.0" ||
            result.id !== id ||
            Object.hasOwn(result, "result") === Object.hasOwn(result, "error")
          )
            throw unavailable();
          if (Object.hasOwn(result, "error")) {
            const error = object(result.error);
            if (typeof error.code !== "number" || !Number.isSafeInteger(error.code))
              throw unavailable();
            const failure = new OaathRpcError(
              "oaath_rpc_rejected",
              error.code,
              error.code === -32500 ? validationDiagnostic(method, params, error.data) : null,
              { cause: result.error },
            );
            if (
              method === "eth_estimateUserOperationGas" &&
              error.code === -32500 &&
              accountValidationReverted(error.data)
            )
              accountValidationRejections.add(failure);
            if (method === "eth_sendUserOperation") submissionRejections.add(failure);
            if ([-32005, -32016, 429].includes(error.code)) transient.add(failure);
            throw failure;
          }
          if (!response.ok)
            throw new OaathRpcError("oaath_rpc_rejected", null, null, { cause: response });
          return result.result;
        })(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            abort.abort();
            reject(unavailable());
          }, timeoutMs);
          cancel = () => {
            abort.abort(signal?.reason);
            reject(aborted());
          };
          if (signal?.aborted) cancel();
          else signal?.addEventListener("abort", cancel, { once: true });
        }),
      ]);
    } catch (error) {
      if (error instanceof OaathRpcError) throw error;
      throw unavailable(error);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (cancel) signal?.removeEventListener("abort", cancel);
      active -= 1;
    }
  }

  return Object.freeze({
    pool(
      endpoints: readonly string[],
      chainId: number,
      methods: readonly string[],
      verifyChain = true,
      headerInput?: Readonly<Record<string, string>>,
    ): RpcRequest {
      const captured = headerInput === undefined ? {} : record(headerInput);
      // Values may be credentials: refuse CR/LF/NUL instead of normalizing them.
      if (
        Object.values(captured).some(
          (value) => typeof value !== "string" || /[\r\n\0]/u.test(value),
        )
      )
        return invalid();
      let headers: Headers;
      try {
        headers = new Headers(captured as Record<string, string>);
      } catch {
        return invalid();
      }
      headers.set("content-type", "application/json");
      const checked = new Set<string>();
      // Pool-local identity includes endpoints, chain binding and headers. Keep
      // only pending work: later reads must still detect new blocks and reorgs.
      const pendingReads = new Map<string, Promise<unknown>>();
      const pendingChainChecks = new Map<string, Promise<unknown>>();
      function readChain(endpoint: string): Promise<unknown> {
        let pending = pendingChainChecks.get(endpoint);
        if (!pending) {
          pending = once(endpoint, "eth_chainId", [], headers).finally(() => {
            pendingChainChecks.delete(endpoint);
          });
          pendingChainChecks.set(endpoint, pending);
        }
        return pending;
      }
      let preferred = 0;
      async function request(method: string, params: readonly unknown[], retry: boolean) {
        const start = preferred;
        for (let attempt = 0; ; attempt += 1) {
          const index = (start + attempt) % endpoints.length;
          const endpoint = endpoints[index];
          if (!endpoint) return invalid();
          try {
            if (verifyChain && method !== "eth_chainId" && !checked.has(endpoint)) {
              if (quantity(await readChain(endpoint)) !== BigInt(chainId))
                throw new OaathRpcError("oaath_rpc_wrong_chain");
              checked.add(endpoint);
            }
            const result =
              method === "eth_chainId" && params.length === 0
                ? await readChain(endpoint)
                : await once(endpoint, method, params, headers);
            if (verifyChain && method === "eth_chainId" && quantity(result) !== BigInt(chainId))
              throw new OaathRpcError("oaath_rpc_wrong_chain");
            if (verifyChain && method === "eth_chainId") checked.add(endpoint);
            preferred = index;
            return result;
          } catch (error) {
            if (
              !retry ||
              attempt + 1 >= attempts ||
              !(error instanceof OaathRpcError) ||
              (!transient.has(error) && error.code !== "oaath_rpc_wrong_chain")
            ) {
              const stage: UserOperationFailureStage | undefined =
                method === "eth_estimateUserOperationGas"
                  ? "estimate"
                  : method === "eth_sendUserOperation"
                    ? "send"
                    : method === "pm_getPaymasterStubData" || method === "pm_getPaymasterData"
                      ? "sponsor"
                      : method === "eth_getUserOperationReceipt"
                        ? "receipt"
                        : undefined;
              if (stage && error instanceof OaathRpcError) {
                // A failed chain check can be shared across different stages.
                // Give each request its own classification and retain the
                // captured account-validation marker only when it already exists.
                const failure = copyRpcError(error);
                Object.defineProperty(failure, "failure", {
                  value: classifyUserOperationError({ stage, error }),
                  enumerable: true,
                });
                throw failure;
              }
              throw error;
            }
            checked.delete(endpoint);
            await retryDelay();
          }
        }
      }
      return async (method, params = [], retry = true) => {
        if (!methods.includes(method)) return invalid();
        if (signal?.aborted) throw aborted();
        if (!COALESCED_READS.has(method)) return request(method, params, retry);
        // Capture the exact wire parameters before a chain check can suspend.
        // A caller mutating its input cannot change another reader's request.
        const encoded = JSON.stringify(params);
        const key = JSON.stringify([method, encoded, retry]);
        let pending = pendingReads.get(key);
        if (!pending) {
          pending = request(method, JSON.parse(encoded), retry).finally(() => {
            pendingReads.delete(key);
          });
          pendingReads.set(key, pending);
        }
        // JSON results previously belonged to one caller. Preserve that
        // isolation, including nested arrays, when sharing a network response.
        try {
          return structuredClone(await pending);
        } catch (error) {
          throw error instanceof OaathRpcError ? copyRpcError(error) : error;
        }
      };
    },
  });
}
