/**
 * The versioned call-review contract shared by Grant and owner reviews.
 *
 * Semantic fields are closed enums; a new value is a new contract version.
 * Identity fields (`account.implementation`, `route`, `fallback.route`) are
 * opaque, bounded, well-formed strings: a new Kernel version or transport adds
 * a value without changing `version`. Consumers check `version` and the
 * semantic fields, and fingerprint identity fields without enumerating them.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureDenseArray, captureRecord } from "@oaath/protocol";
import { clientFail, clientFailure } from "./errors.js";

export const OAATH_CALLS_REVIEW_VERSION = "oaath-calls-review-v1" as const;

const IDENTITY = /^[a-z0-9]+(?:[.:-][a-z0-9]+)*$/u;
const MAX_IDENTITY_LENGTH = 64;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/u;
const DATA = /^0x(?:[0-9a-fA-F]{2})*$/u;
const MAX_CALLS = 64;

export interface OaathCallsReviewContract {
  readonly version: typeof OAATH_CALLS_REVIEW_VERSION;
  /** Semantic: which authority signs. */
  readonly signer: "session" | "owner";
  /** Semantic: where each limit is enforced. `none` means nothing enforces it. */
  readonly enforcement: Readonly<{
    calls: "onchain" | "none";
    expiry: "onchain" | "client" | "none";
    operationCount: "onchain" | "none";
  }>;
  /** Semantic: whether account validation was estimated before signing. */
  readonly validation: "not-estimated" | "estimated" | "account-rejected";
  /** Semantic `condition` and `feePayer`; `route` is identity. */
  readonly fallback: Readonly<{
    route: string;
    feePayer: `0x${string}`;
    condition: "conclusive_bundler_rejection";
  }> | null;
  readonly chainId: number;
  /** `implementation` is identity, e.g. `kernel:0.3.3`. */
  readonly account: Readonly<{ address: `0x${string}`; implementation: string }>;
  /** Identity: the selected submission route, e.g. `erc4337-bundler`. */
  readonly route: string;
  readonly calls: readonly Readonly<{
    target: `0x${string}`;
    value: string;
    data: `0x${string}`;
  }>[];
}

/** The opaque account implementation identity of one Kernel version. */
export function kernelImplementation(kernelVersion: string): string {
  return `kernel:${kernelVersion}`;
}

function identity(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > MAX_IDENTITY_LENGTH || !IDENTITY.test(value))
    return clientFail("oaath_client_input_invalid", `${label} is not a well-formed identity`);
  return value;
}

function oneOf<const T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== "string" || !allowed.includes(value as T))
    return clientFail("oaath_client_input_invalid", `${label} is unsupported`);
  return value as T;
}

function address(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value))
    return clientFail("oaath_client_input_invalid", `${label} is not an address`);
  return value as `0x${string}`;
}

function enforcement(
  value: unknown,
  signer: OaathCallsReviewContract["signer"],
  context: CaptureContext,
): OaathCallsReviewContract["enforcement"] {
  const record = captureRecord(
    value,
    "review enforcement",
    context,
    clientFailure("oaath_client_input_invalid"),
  );
  const captured = Object.freeze({
    calls: oneOf(record.calls, ["onchain", "none"], "review enforcement calls"),
    expiry: oneOf(record.expiry, ["onchain", "client", "none"], "review enforcement expiry"),
    operationCount: oneOf(record.operationCount, ["onchain", "none"], "review operation count"),
  });
  const consistent =
    signer === "session"
      ? captured.calls === "onchain" &&
        captured.expiry === "onchain" &&
        captured.operationCount === "onchain"
      : captured.calls === "none" && captured.operationCount === "none";
  if (!consistent)
    return clientFail("oaath_client_input_invalid", "review enforcement contradicts its signer");
  return captured;
}

function fallback(value: unknown, context: CaptureContext): OaathCallsReviewContract["fallback"] {
  if (value === null) return null;
  const record = captureRecord(
    value,
    "review fallback",
    context,
    clientFailure("oaath_client_input_invalid"),
  );
  return Object.freeze({
    route: identity(record.route, "review fallback route"),
    feePayer: address(record.feePayer, "review fallback fee payer"),
    condition: oneOf(
      record.condition,
      ["conclusive_bundler_rejection"],
      "review fallback condition",
    ),
  });
}

function calls(value: unknown, context: CaptureContext): OaathCallsReviewContract["calls"] {
  const fail = clientFailure("oaath_client_input_invalid");
  const entries = captureDenseArray(value, "review calls", context, fail);
  if (entries.length < 1 || entries.length > MAX_CALLS) return fail("review calls are invalid");
  return Object.freeze(
    entries.map((entry) => {
      const record = captureRecord(entry, "review call", context, fail);
      if (
        typeof record.value !== "string" ||
        !DECIMAL.test(record.value) ||
        typeof record.data !== "string" ||
        !DATA.test(record.data)
      )
        return fail("review call is invalid");
      return Object.freeze({
        target: address(record.target, "review call target"),
        value: record.value,
        data: record.data as `0x${string}`,
      });
    }),
  );
}

/**
 * Captures the contract fields of a Grant or owner call review. A review with
 * any other `version` fails with `oaath_client_review_version_unsupported`;
 * malformed or contradictory contract fields fail with
 * `oaath_client_input_invalid`. Fields outside the contract are not returned.
 */
export function parseOaathCallsReview(value: unknown): Readonly<OaathCallsReviewContract> {
  const context: CaptureContext = new WeakSet();
  const record = captureRecord(
    value,
    "calls review",
    context,
    clientFailure("oaath_client_input_invalid"),
  );
  if (record.version !== OAATH_CALLS_REVIEW_VERSION)
    return clientFail(
      "oaath_client_review_version_unsupported",
      "calls review version is unsupported",
    );
  const signer = oneOf(record.signer, ["session", "owner"], "review signer");
  const chainId = record.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1)
    return clientFail("oaath_client_input_invalid", "review chain is invalid");
  const account = captureRecord(
    record.account,
    "review account",
    context,
    clientFailure("oaath_client_input_invalid"),
  );
  return Object.freeze({
    version: OAATH_CALLS_REVIEW_VERSION,
    signer,
    enforcement: enforcement(record.enforcement, signer, context),
    validation: oneOf(
      record.validation,
      ["not-estimated", "estimated", "account-rejected"],
      "review validation",
    ),
    fallback: fallback(record.fallback, context),
    chainId,
    account: Object.freeze({
      address: address(account.address, "review account address"),
      implementation: identity(account.implementation, "review account implementation"),
    }),
    route: identity(record.route, "review route"),
    calls: calls(record.calls, context),
  });
}
