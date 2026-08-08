/**
 * Closed wallet-RPC capability vocabulary.
 *
 * This table translates standards metadata into the existing Grant execution
 * path. It is not a runtime plugin system: handlers are internal, fixed, and
 * may only preserve or tighten the calls captured by the provider boundary.
 *
 * @author taek <leekt216@gmail.com>
 */
import { OAATH_ISSUER_VERSION, parseIssuerIdentity } from "@oaath/protocol";
import type { Hash } from "viem";
import type {
  CapturedJsonObject,
  CapturedWalletCall,
  CapturedWalletCapabilities,
  CapturedWalletPaymasterService,
} from "./capture.js";
import {
  type CapturedWalletValidityTimeRange,
  captureErc7902StaticPaymasterConfiguration,
  captureErc7902ValidityTimeRange,
  type Erc7902StaticPaymasterConfiguration,
  hashCapturedErc7902PreparedPaymaster,
} from "./erc7902.js";
import {
  ATOMICITY_UNSUPPORTED,
  INTERNAL_ERROR,
  invalidProviderParams,
  rpcFail,
  UNSUPPORTED_CAPABILITY,
} from "./errors.js";

export type WalletCapabilityScope = "bundle" | "call";
export type WalletCapabilityMethod =
  | "wallet_sendCalls"
  | "wallet_prepareCalls"
  | "wallet_sendPreparedCalls";
type WalletCapabilityStatus = "final" | "review" | "draft" | "experimental";

interface WalletCapabilityContext {
  readonly atomicExecution: boolean;
  readonly paymasterService?: boolean;
  readonly staticPaymasterConfigurationHash: Hash | null;
  readonly validityTimeRange?: boolean;
}

interface WalletCapabilityBaseEffect {
  readonly atomic: boolean;
  readonly calls: readonly CapturedWalletCall[];
}

export type WalletPaymasterSelection =
  | Readonly<{
      readonly kind: "erc7677";
      readonly url: string;
      readonly context: CapturedJsonObject;
    }>
  | Readonly<{
      readonly kind: "erc7902-static";
      readonly configuration: CapturedJsonObject;
    }>
  | null;

export interface WalletCapabilityEffect extends WalletCapabilityBaseEffect {
  readonly paymaster: WalletPaymasterSelection;
  readonly validityTimeRange: Readonly<CapturedWalletValidityTimeRange> | null;
}

/** Normalized selection derived once from the retained exact request value. */
export interface CapturedWalletStaticPaymasterConfiguration
  extends Erc7902StaticPaymasterConfiguration {
  readonly configurationHash: Hash;
}

interface WalletCapabilityHandler<Captured, Response> {
  readonly key: string;
  readonly status: WalletCapabilityStatus;
  readonly metadataMethods: readonly WalletCapabilityMethod[];
  readonly metadataScopes: readonly WalletCapabilityScope[];
  readonly advertise: (context: Readonly<WalletCapabilityContext>) => Readonly<Response> | null;
  readonly capture: (value: unknown, scope: WalletCapabilityScope) => Readonly<Captured>;
  readonly apply?: (input: {
    readonly captured: Readonly<Captured>;
    readonly calls: readonly CapturedWalletCall[];
    readonly chainId: number;
    readonly context: Readonly<WalletCapabilityContext>;
  }) => Readonly<WalletCapabilityBaseEffect>;
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
  metadataMethods: Object.freeze([]),
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

const PAYMASTER_SERVICE_HANDLER: WalletCapabilityHandler<
  CapturedWalletPaymasterService,
  Readonly<{ supported: true }>
> = Object.freeze({
  key: "paymasterService",
  status: "review",
  metadataMethods: Object.freeze([
    "wallet_sendCalls",
    "wallet_prepareCalls",
    "wallet_sendPreparedCalls",
  ] as const),
  metadataScopes: Object.freeze(["bundle"] as const),
  advertise(context: Readonly<WalletCapabilityContext>) {
    return context.paymasterService === true ? Object.freeze({ supported: true as const }) : null;
  },
  capture(value: unknown, scope: WalletCapabilityScope) {
    if (scope !== "bundle" || value === null || typeof value !== "object" || Array.isArray(value)) {
      return invalidProviderParams();
    }
    const capability = value as CapturedJsonObject;
    for (const key of Object.keys(capability)) {
      if (key !== "url" && key !== "context" && key !== "optional") {
        return invalidProviderParams();
      }
    }
    if (!Object.hasOwn(capability, "url") || !Object.hasOwn(capability, "context")) {
      return invalidProviderParams();
    }

    let url: string;
    try {
      url = parseIssuerIdentity({ version: OAATH_ISSUER_VERSION, url: capability.url }).url;
    } catch {
      return invalidProviderParams();
    }
    const context = capability.context;
    if (context === null || typeof context !== "object" || Array.isArray(context)) {
      return invalidProviderParams();
    }

    const captured = {
      url,
      context: context as CapturedJsonObject,
      optional: capability.optional === true,
    };
    Object.setPrototypeOf(captured, null);
    return Object.freeze(captured);
  },
});

const STATIC_PAYMASTER_CONFIGURATION_HANDLER: WalletCapabilityHandler<
  CapturedWalletStaticPaymasterConfiguration,
  Readonly<{ supported: true; status: "experimental" }>
> = Object.freeze({
  key: "staticPaymasterConfiguration",
  status: "experimental",
  metadataMethods: Object.freeze(["wallet_sendCalls"] as const),
  metadataScopes: Object.freeze(["bundle"] as const),
  advertise(context: Readonly<WalletCapabilityContext>) {
    return typeof context.staticPaymasterConfigurationHash === "string"
      ? Object.freeze({ supported: true as const, status: "experimental" as const })
      : null;
  },
  capture(value: unknown, scope: WalletCapabilityScope) {
    if (scope !== "bundle") return invalidProviderParams();
    try {
      const captured = captureErc7902StaticPaymasterConfiguration(value);
      return Object.freeze({
        optional: captured.optional,
        paymaster: captured.paymaster,
        configurationHash: hashCapturedErc7902PreparedPaymaster(captured.paymaster),
      });
    } catch {
      return invalidProviderParams();
    }
  },
});

const VALIDITY_TIME_RANGE_HANDLER: WalletCapabilityHandler<
  CapturedWalletValidityTimeRange,
  Readonly<{ supported: true; status: "experimental" }>
> = Object.freeze({
  key: "validityTimeRange",
  status: "experimental",
  metadataMethods: Object.freeze([
    "wallet_sendCalls",
    "wallet_prepareCalls",
    "wallet_sendPreparedCalls",
  ] as const),
  metadataScopes: Object.freeze(["bundle"] as const),
  advertise(context: Readonly<WalletCapabilityContext>) {
    return context.validityTimeRange === true
      ? Object.freeze({ supported: true as const, status: "experimental" as const })
      : null;
  },
  capture(value: unknown, scope: WalletCapabilityScope) {
    if (scope !== "bundle") return invalidProviderParams();
    try {
      return captureErc7902ValidityTimeRange(value);
    } catch {
      return invalidProviderParams();
    }
  },
});

const CAPABILITY_HANDLERS = Object.freeze([
  ATOMIC_HANDLER,
  PAYMASTER_SERVICE_HANDLER,
  STATIC_PAYMASTER_CONFIGURATION_HANDLER,
  VALIDITY_TIME_RANGE_HANDLER,
]);

/** Whether a named bundle/call capability has an implemented closed handler. */
export function isHandledWalletCapability(
  key: string,
  method: WalletCapabilityMethod,
  scope: WalletCapabilityScope,
): boolean {
  return CAPABILITY_HANDLERS.some(
    (handler) =>
      handler.key === key &&
      (handler.metadataMethods as readonly WalletCapabilityMethod[]).includes(method) &&
      (handler.metadataScopes as readonly WalletCapabilityScope[]).includes(scope),
  );
}

/** Exact capture for EIP-5792's built-in request-side atomic control. */
export function captureAtomicCapability(value: unknown): Readonly<AtomicCapability> {
  return ATOMIC_HANDLER.capture(value, "bundle");
}

/** Exact capture for one already-isolated ERC-7677 bundle capability value. */
export function capturePaymasterServiceCapability(
  value: CapturedJsonObject,
): Readonly<CapturedWalletPaymasterService> {
  return PAYMASTER_SERVICE_HANDLER.capture(value, "bundle");
}

/** Exact capture for one already-isolated ERC-7902 bundle capability value. */
export function captureStaticPaymasterConfigurationCapability(
  value: CapturedJsonObject,
): Readonly<CapturedWalletStaticPaymasterConfiguration> {
  return STATIC_PAYMASTER_CONFIGURATION_HANDLER.capture(value, "bundle");
}

/** Exact capture for one already-isolated ERC-7902 bundle validity range. */
export function captureValidityTimeRangeCapability(
  value: CapturedJsonObject,
): Readonly<CapturedWalletValidityTimeRange> {
  return VALIDITY_TIME_RANGE_HANDLER.capture(value, "bundle");
}

/** Apply all implemented capability effects before operation preparation. */
export function applyWalletCapabilities(input: {
  readonly atomic: Readonly<AtomicCapability>;
  readonly calls: readonly CapturedWalletCall[];
  readonly chainId: number;
  readonly atomicExecution: boolean;
  readonly capabilities?: Readonly<CapturedWalletCapabilities>;
  readonly registeredPaymasterServiceUrl: string | null;
  readonly staticPaymasterConfigurationHash: Hash | null;
}): Readonly<WalletCapabilityEffect> {
  const requestedPaymasterService = input.capabilities?.paymasterService;
  const requestedStaticPaymaster = input.capabilities?.staticPaymasterConfiguration;
  if (requestedPaymasterService !== undefined && requestedStaticPaymaster !== undefined) {
    return invalidProviderParams();
  }

  const applyAtomic = ATOMIC_HANDLER.apply;
  if (applyAtomic === undefined) return rpcFail(INTERNAL_ERROR);
  const atomic = applyAtomic({
    captured: input.atomic,
    calls: input.calls,
    chainId: input.chainId,
    context: Object.freeze({
      atomicExecution: input.atomicExecution,
      staticPaymasterConfigurationHash: input.staticPaymasterConfigurationHash,
    }),
  });

  let paymaster: WalletPaymasterSelection = null;
  if (requestedPaymasterService !== undefined) {
    if (input.registeredPaymasterServiceUrl === requestedPaymasterService.url) {
      paymaster = Object.freeze({
        kind: "erc7677" as const,
        url: requestedPaymasterService.url,
        context: requestedPaymasterService.context,
      });
    } else if (!requestedPaymasterService.optional) {
      return rpcFail(UNSUPPORTED_CAPABILITY);
    }
  } else if (requestedStaticPaymaster !== undefined) {
    if (
      input.staticPaymasterConfigurationHash !== null &&
      input.staticPaymasterConfigurationHash === requestedStaticPaymaster.configurationHash
    ) {
      const configuration = input.capabilities?.values.staticPaymasterConfiguration;
      if (configuration === undefined) return rpcFail(INTERNAL_ERROR);
      paymaster = Object.freeze({
        kind: "erc7902-static" as const,
        configuration,
      });
    } else if (!requestedStaticPaymaster.optional) {
      return rpcFail(UNSUPPORTED_CAPABILITY);
    }
  }

  return Object.freeze({
    atomic: atomic.atomic,
    calls: atomic.calls,
    paymaster,
    validityTimeRange: input.capabilities?.validityTimeRange ?? null,
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
