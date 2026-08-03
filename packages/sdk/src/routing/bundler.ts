/**
 * Bundler health and pre-acceptance classification. The SDK consumer owns every
 * transport: it implements `OaathBundlerProbeCapability`, and this module only
 * classifies the evidence that capability returns.
 *
 * Exactly two evidence shapes can authorize the `EntryPoint.handleOps` fallback,
 * and both must be conclusive before submission:
 *
 * - probe evidence in which a reachable bundler reports that it is not accepting
 *   operations (`absent`) or does not serve this chain/EntryPoint (`unsupported`);
 * - pre-acceptance evidence carrying a closed ERC-4337 rejection code
 *   (`unsupported`).
 *
 * Everything else — timeout, disconnect, transport crash, unknown error code,
 * malformed or hostile evidence — classifies as `unreadable`, which authorizes
 * no fallback and no resubmission.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureDenseArray } from "@oaath/protocol";
import { type OaathBundlerCapability, routingAddress, routingChainId } from "./capabilities.js";
import { capabilityInvalid, exactRoutingRecord, inputInvalid } from "./types.js";

const MAX_TIMEOUT_MS = 60_000;
const MAX_SUPPORTED_ENTRY_POINTS = 32;

/**
 * ERC-4337 bundler error codes that conclusively refuse one operation before
 * acceptance. Any other code, including generic JSON-RPC failures such as
 * -32603 and -32000, is inconclusive.
 */
export const OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES: readonly number[] = Object.freeze([
  -32500, -32501, -32502, -32503, -32504, -32505, -32506, -32507, -32521,
]);

export interface OaathBundlerProbeRequest {
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
}

/** The consumer-implemented pre-submission probe. Routing never builds a transport. */
export interface OaathBundlerProbeCapability {
  readonly probe: (request: Readonly<OaathBundlerProbeRequest>) => Promise<unknown>;
}

/**
 * The evidence a probe must return: whether the bundler is accepting work, which
 * chain it serves, and which EntryPoints it supports.
 */
export interface OaathBundlerProbeEvidence {
  readonly accepting: boolean;
  readonly chainId: number;
  readonly supportedEntryPoints: readonly `0x${string}`[];
}

/**
 * Pre-acceptance evidence for one prepared operation. `outcome` is `accepted`
 * with a `null` code when the bundler validated the operation, and `rejected`
 * with the bundler's JSON-RPC error `code` when it refused the operation before
 * accepting it. A `null` or unknown code is never conclusive.
 */
export interface OaathBundlerAcceptanceEvidence {
  readonly outcome: "accepted" | "rejected";
  readonly code: number | null;
}

export interface OaathBundlerProbeInput {
  readonly capability: OaathBundlerProbeCapability;
  readonly request: Readonly<OaathBundlerProbeRequest>;
  readonly timeoutMs: number;
}

class ProbeTimeout extends Error {}

const unreadableEvidence: (message: string) => never = (message) => {
  throw new Error(message);
};

/**
 * Classifies probe evidence against the chain and EntryPoint the prepared
 * operation is bound to. Evidence is captured in full before it is classified,
 * so malformed evidence is `unreadable` and never a conclusive `absent`.
 */
export function classifyBundlerProbe(
  evidence: unknown,
  request: Readonly<OaathBundlerProbeRequest>,
): OaathBundlerCapability {
  const expectedChainId = routingChainId(request.chainId, inputInvalid);
  const expectedEntryPoint = routingAddress(request.entryPoint, "bundler EntryPoint", inputInvalid);
  try {
    const context: CaptureContext = new WeakSet();
    const record = exactRoutingRecord(
      evidence,
      ["accepting", "chainId", "supportedEntryPoints"],
      "bundler probe evidence",
      context,
      unreadableEvidence,
    );
    if (typeof record.accepting !== "boolean") return "unreadable";
    const chainId = routingChainId(record.chainId, unreadableEvidence);
    const entryPoints = captureDenseArray(
      record.supportedEntryPoints,
      "bundler supported EntryPoints",
      context,
      unreadableEvidence,
    );
    if (entryPoints.length > MAX_SUPPORTED_ENTRY_POINTS) return "unreadable";
    const supported = entryPoints.map((entryPoint) =>
      routingAddress(entryPoint, "bundler supported EntryPoint", unreadableEvidence),
    );

    if (!record.accepting) return "absent";
    if (chainId !== expectedChainId) return "unsupported";
    return supported.includes(expectedEntryPoint) ? "available" : "unsupported";
  } catch {
    return "unreadable";
  }
}

/**
 * Classifies one pre-acceptance response. Only a closed ERC-4337 rejection code
 * conclusively refuses the bundler route; every other rejection is `unreadable`
 * and keeps the operation on the bundler route.
 */
export function classifyBundlerAcceptance(evidence: unknown): OaathBundlerCapability {
  try {
    const record = exactRoutingRecord(
      evidence,
      ["outcome", "code"],
      "bundler acceptance evidence",
      new WeakSet(),
      unreadableEvidence,
    );
    if (record.outcome === "accepted" && record.code === null) return "available";
    if (record.outcome !== "rejected") return "unreadable";
    if (typeof record.code !== "number" || !Number.isSafeInteger(record.code)) return "unreadable";
    return OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES.includes(record.code)
      ? "unsupported"
      : "unreadable";
  } catch {
    return "unreadable";
  }
}

/**
 * Invokes the consumer's probe under a bounded timeout and classifies its
 * evidence. A throw, a rejection, or a deadline expiry classifies as
 * `unreadable`: this is the enforced path, so no caller can turn a transport
 * failure into a conclusive fallback authorization.
 */
export async function probeBundlerCapability(
  input: OaathBundlerProbeInput,
): Promise<OaathBundlerCapability> {
  const context: CaptureContext = new WeakSet();
  const record = exactRoutingRecord(
    input,
    ["capability", "request", "timeoutMs"],
    "bundler probe input",
    context,
    capabilityInvalid,
  );
  const capability = exactRoutingRecord(
    record.capability,
    ["probe"],
    "bundler probe capability",
    context,
    capabilityInvalid,
  );
  if (typeof capability.probe !== "function") {
    return capabilityInvalid("bundler probe capability is invalid");
  }
  const probe = capability.probe as OaathBundlerProbeCapability["probe"];
  const requestRecord = exactRoutingRecord(
    record.request,
    ["chainId", "entryPoint"],
    "bundler probe request",
    context,
    inputInvalid,
  );
  const request = Object.freeze({
    chainId: routingChainId(requestRecord.chainId, inputInvalid),
    entryPoint: routingAddress(requestRecord.entryPoint, "bundler EntryPoint", inputInvalid),
  });
  const timeoutMs = record.timeoutMs;
  if (
    typeof timeoutMs !== "number" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    return inputInvalid("bundler probe timeout is invalid");
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const evidence = await Promise.race([
      Promise.resolve().then(() => Reflect.apply(probe, undefined, [request])),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new ProbeTimeout()), timeoutMs);
      }),
    ]);
    return classifyBundlerProbe(evidence, request);
  } catch {
    return "unreadable";
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
