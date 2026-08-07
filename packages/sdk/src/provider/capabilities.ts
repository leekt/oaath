/**
 * Closed wallet-RPC capability vocabulary.
 *
 * This table translates standards metadata into the existing Grant execution
 * path. It is not a runtime plugin system: handlers are internal, fixed, and
 * may only preserve or tighten the calls captured by the provider boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CapturedWalletCall } from "./capture.js";
import { ATOMICITY_UNSUPPORTED, INTERNAL_ERROR, invalidProviderParams, rpcFail } from "./errors.js";

export type WalletCapabilityScope = "bundle" | "call";
type WalletCapabilityStatus = "final" | "review" | "draft" | "experimental";

interface WalletCapabilityContext {
  readonly atomicExecution: boolean;
}

interface WalletCapabilityEffect {
  readonly atomic: boolean;
  readonly calls: readonly CapturedWalletCall[];
}

interface WalletCapabilityHandler<Captured, Response> {
  readonly key: string;
  readonly status: WalletCapabilityStatus;
  readonly metadataScopes: readonly WalletCapabilityScope[];
  readonly advertise: (context: Readonly<WalletCapabilityContext>) => Readonly<Response> | null;
  readonly capture: (value: unknown, scope: WalletCapabilityScope) => Readonly<Captured>;
  readonly apply: (input: {
    readonly captured: Readonly<Captured>;
    readonly calls: readonly CapturedWalletCall[];
    readonly chainId: number;
    readonly context: Readonly<WalletCapabilityContext>;
  }) => Readonly<WalletCapabilityEffect>;
}

interface AtomicCapability {
  readonly atomicRequired: boolean;
}

const ATOMIC_HANDLER: WalletCapabilityHandler<
  AtomicCapability,
  Readonly<{ status: "supported" }>
> = Object.freeze({
  key: "atomic",
  status: "final",
  // EIP-5792 expresses the request through top-level `atomicRequired`, not
  // through bundle/call capability metadata.
  metadataScopes: Object.freeze([]),
  advertise(context: Readonly<WalletCapabilityContext>) {
    return context.atomicExecution ? Object.freeze({ status: "supported" as const }) : null;
  },
  capture(value: unknown, scope: WalletCapabilityScope) {
    if (scope !== "bundle" || typeof value !== "boolean") return invalidProviderParams();
    return Object.freeze({ atomicRequired: value });
  },
  apply(input: {
    readonly captured: Readonly<AtomicCapability>;
    readonly calls: readonly CapturedWalletCall[];
    readonly chainId: number;
    readonly context: Readonly<WalletCapabilityContext>;
  }) {
    if (!Number.isSafeInteger(input.chainId) || input.chainId < 1 || input.calls.length === 0) {
      return rpcFail(INTERNAL_ERROR);
    }
    if (input.captured.atomicRequired && !input.context.atomicExecution) {
      return rpcFail(ATOMICITY_UNSUPPORTED);
    }
    return Object.freeze({
      atomic: input.context.atomicExecution,
      calls: input.calls,
    });
  },
});

const CAPABILITY_HANDLERS = Object.freeze([ATOMIC_HANDLER]);

/** Whether a named bundle/call capability has an implemented closed handler. */
export function isHandledWalletCapability(key: string, scope: WalletCapabilityScope): boolean {
  return CAPABILITY_HANDLERS.some(
    (handler) => handler.key === key && handler.metadataScopes.includes(scope),
  );
}

/** Exact capture for EIP-5792's built-in request-side atomic control. */
export function captureAtomicCapability(value: unknown): Readonly<AtomicCapability> {
  return ATOMIC_HANDLER.capture(value, "bundle");
}

/** Apply all implemented capability effects before operation preparation. */
export function applyWalletCapabilities(input: {
  readonly atomic: Readonly<AtomicCapability>;
  readonly calls: readonly CapturedWalletCall[];
  readonly chainId: number;
  readonly atomicExecution: boolean;
}): Readonly<WalletCapabilityEffect> {
  return ATOMIC_HANDLER.apply({
    captured: input.atomic,
    calls: input.calls,
    chainId: input.chainId,
    context: Object.freeze({ atomicExecution: input.atomicExecution }),
  });
}

/** Advertise only capabilities implemented for this connected execution route. */
export function advertiseWalletCapabilities(
  context: Readonly<WalletCapabilityContext>,
): Readonly<Record<string, unknown>> {
  const advertised: Record<string, unknown> = Object.create(null);
  for (const handler of CAPABILITY_HANDLERS) {
    const response = handler.advertise(context);
    if (response !== null) advertised[handler.key] = response;
  }
  return Object.freeze(advertised);
}
