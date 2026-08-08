/**
 * The versioned service bootstrap document.
 *
 * An application connects to one OAAth service URL; everything else the realm
 * needs is authenticated service context delivered by this document during
 * `connect()`: the client identity the deployment registered, the logical
 * account and owner credential the owner holds, and the chains the service can
 * execute on. The application never assembles these facts itself, so a hostile
 * or misconfigured page cannot choose a different account, owner identity, or
 * chain surface than the deployment registered.
 *
 * The document is parsed exactly and fails closed: an unknown field, an
 * unsupported version, or a non-canonical value rejects the whole bootstrap
 * rather than composing a realm on partially trusted context.
 *
 * @author taek <leekt216@gmail.com>
 */
import { captureCanonicalHttpsUrl } from "./actors/issuer.js";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import { captureKernelAccountProfile, type KernelAccountProfile } from "./identity-profile.js";
import { parseClientId } from "./ids.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureDenseArray,
  exactRecord,
} from "./internal/exact-record.js";

export const OAATH_SERVICE_BOOTSTRAP_VERSION = "oaath.service-bootstrap/v3" as const;

const MAX_REDIRECT_URIS = 8;
const MAX_CHAINS = 32;
const MAX_NAME_LENGTH = 256;
const MAX_HANDLE_LENGTH = 256;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;

export interface ServiceBootstrapApplication {
  readonly applicationId: string;
  readonly applicationName: string;
  readonly clientId: string;
  /** Registered redirect targets; the SDK selects a same-origin one locally. */
  readonly redirectUris: readonly string[];
}

export interface ServiceBootstrapChain {
  readonly chainId: number;
  /**
   * Whether the service serves finalized per-grant usage evidence for this
   * chain. Without it, session coverage is inconclusive and execution denies.
   */
  readonly usage: boolean;
  /** EOA fee payer snapshot for the handleOps fallback, or null. */
  readonly feePayer: Readonly<{ address: `0x${string}`; balance: string }> | null;
  /**
   * Deployment-registered ERC-7677 provider for this chain, or null. The SDK
   * derives its same-service proxy URL from the connected OAAth service URL;
   * this identifier is configuration evidence, never an application endpoint.
   */
  readonly paymasterService: Readonly<ServiceBootstrapPaymasterService> | null;
  /**
   * Deployment-authenticated commitment to the one exact ERC-7902 static
   * paymaster configuration this chain accepts, or null. The bootstrap never
   * interprets or carries the potentially large paymaster data itself.
   */
  readonly staticPaymasterConfigurationHash: `0x${string}` | null;
}

export interface ServiceBootstrapPaymasterService {
  readonly providerId: string;
}

/**
 * Where the scoped session/operator key lives. Custody modes are different
 * trust models, so the deployment declares one and every party fails closed on
 * a mode it does not implement — a custody mode is never silently substituted.
 *
 * - `frontend` — the SDK generates and holds a non-extractable local key; the
 *   service never sees session private material.
 * - `application_backend` — the integrating application's backend holds the
 *   key in its own KMS/HSM and signs through a registered, authenticated
 *   signer capability.
 * - `oaath_hosted` — the service holds a tightly scoped operator key in its
 *   own KMS/HSM and signs server-side.
 */
export type ServiceBootstrapSessionSignerMode = "frontend" | "application_backend" | "oaath_hosted";

export interface ServiceBootstrapSessionSigner {
  readonly mode: ServiceBootstrapSessionSignerMode;
  /** Deployment-registered signer provider identity; null exactly for frontend. */
  readonly providerId: string | null;
}

const FRONTEND_SESSION_SIGNER: Readonly<ServiceBootstrapSessionSigner> = Object.freeze({
  mode: "frontend",
  providerId: null,
});

export interface ServiceBootstrap {
  readonly version: typeof OAATH_SERVICE_BOOTSTRAP_VERSION;
  readonly application: Readonly<ServiceBootstrapApplication>;
  /** Opaque issuer-scoped handle of the authenticated user. */
  readonly userHandle: string;
  /** The logical account, including the owner credential the owner reviews. */
  readonly account: Readonly<KernelAccountProfile>;
  /**
   * Caller-bound ECDSA owner validator module, or null. Kernel v4 pins no
   * ECDSA validator deployment, so an ecdsa owner credential requires exactly
   * this deployment fact; other owner kinds resolve pinned modules and carry
   * none.
   */
  readonly ownerValidator: `0x${string}` | null;
  readonly chains: readonly Readonly<ServiceBootstrapChain>[];
  /** The deployment's explicitly declared session-key custody. */
  readonly sessionSigner: Readonly<ServiceBootstrapSessionSigner>;
}

function boundedText(value: unknown, max: number, label: string, fail: CaptureFailure): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) {
    return fail(`${label} must be a bounded non-empty string`);
  }
  return value;
}

function captureChain(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<ServiceBootstrapChain> {
  const record = exactRecord(
    value,
    ["chainId", "usage", "feePayer", "paymasterService", "staticPaymasterConfigurationHash"],
    "service bootstrap chain",
    context,
    fail,
  );
  const chainId = record.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return fail("service bootstrap chainId must be a positive integer");
  }
  if (typeof record.usage !== "boolean") {
    return fail("service bootstrap chain usage must be a boolean");
  }
  let feePayer: Readonly<{ address: `0x${string}`; balance: string }> | null = null;
  if (record.feePayer !== null) {
    const payer = exactRecord(
      record.feePayer,
      ["address", "balance"],
      "service bootstrap fee payer",
      context,
      fail,
    );
    if (typeof payer.address !== "string" || !ADDRESS.test(payer.address)) {
      return fail("service bootstrap fee payer address must be a lowercase address");
    }
    if (typeof payer.balance !== "string" || !DECIMAL_UINT.test(payer.balance)) {
      return fail("service bootstrap fee payer balance must be a canonical decimal");
    }
    feePayer = Object.freeze({ address: payer.address as `0x${string}`, balance: payer.balance });
  }
  let paymasterService: Readonly<ServiceBootstrapPaymasterService> | null = null;
  if (record.paymasterService !== null) {
    const service = exactRecord(
      record.paymasterService,
      ["providerId"],
      "service bootstrap paymaster service",
      context,
      fail,
    );
    paymasterService = Object.freeze({
      providerId: boundedText(
        service.providerId,
        MAX_NAME_LENGTH,
        "service bootstrap paymaster provider",
        fail,
      ),
    });
  }
  const staticPaymasterConfigurationHash = record.staticPaymasterConfigurationHash;
  if (
    staticPaymasterConfigurationHash !== null &&
    (typeof staticPaymasterConfigurationHash !== "string" ||
      !HASH.test(staticPaymasterConfigurationHash))
  ) {
    return fail("service bootstrap static paymaster commitment must be a lowercase hash or null");
  }
  return Object.freeze({
    chainId,
    usage: record.usage,
    feePayer,
    paymasterService,
    staticPaymasterConfigurationHash: staticPaymasterConfigurationHash as `0x${string}` | null,
  });
}

function captureSessionSigner(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<ServiceBootstrapSessionSigner> {
  const record = exactRecord(
    value,
    ["mode", "providerId"],
    "service bootstrap session signer",
    context,
    fail,
  );
  const mode = record.mode;
  if (mode !== "frontend" && mode !== "application_backend" && mode !== "oaath_hosted") {
    return fail("service bootstrap session signer mode is unsupported");
  }
  if (mode === "frontend") {
    if (record.providerId !== null) {
      return fail("service bootstrap frontend session signer names no provider");
    }
    return FRONTEND_SESSION_SIGNER;
  }
  return Object.freeze({
    mode,
    providerId: boundedText(
      record.providerId,
      MAX_NAME_LENGTH,
      "service bootstrap session signer provider",
      fail,
    ),
  });
}

export function captureServiceBootstrap(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<ServiceBootstrap> {
  const record = exactRecord(
    value,
    [
      "version",
      "application",
      "userHandle",
      "account",
      "ownerValidator",
      "chains",
      "sessionSigner",
    ],
    "service bootstrap",
    context,
    fail,
  );
  if (record.version !== OAATH_SERVICE_BOOTSTRAP_VERSION) {
    return fail("service bootstrap version is unsupported");
  }
  const application = exactRecord(
    record.application,
    ["applicationId", "applicationName", "clientId", "redirectUris"],
    "service bootstrap application",
    context,
    fail,
  );
  const redirectEntries = captureDenseArray(
    application.redirectUris,
    "service bootstrap redirect URIs",
    context,
    fail,
  );
  if (redirectEntries.length < 1 || redirectEntries.length > MAX_REDIRECT_URIS) {
    return fail("service bootstrap must register 1 to 8 redirect URIs");
  }
  const chainEntries = captureDenseArray(record.chains, "service bootstrap chains", context, fail);
  if (chainEntries.length < 1 || chainEntries.length > MAX_CHAINS) {
    return fail("service bootstrap must advertise 1 to 32 chains");
  }
  const chainIds = new Set<number>();
  const chains = chainEntries.map((entry) => {
    const chain = captureChain(entry, context, fail);
    if (chainIds.has(chain.chainId)) {
      return fail("service bootstrap chains repeat a chainId");
    }
    chainIds.add(chain.chainId);
    return chain;
  });
  const account = captureKernelAccountProfile(record.account, context, fail);
  let ownerValidator: `0x${string}` | null = null;
  if (record.ownerValidator !== null) {
    if (typeof record.ownerValidator !== "string" || !ADDRESS.test(record.ownerValidator)) {
      return fail("service bootstrap owner validator must be a lowercase address");
    }
    ownerValidator = record.ownerValidator as `0x${string}`;
  }
  // An ecdsa owner has no pinned validator module, so the deployment fact is
  // required exactly when the owner credential is ecdsa and meaningless
  // otherwise; a stray validator for another kind is refused, not ignored.
  if ((account.ownerCredential.kind === "ecdsa") !== (ownerValidator !== null)) {
    return fail("service bootstrap owner validator does not match the owner credential kind");
  }
  return Object.freeze({
    version: OAATH_SERVICE_BOOTSTRAP_VERSION,
    application: Object.freeze({
      applicationId: parseClientId(application.applicationId, fail),
      applicationName: boundedText(
        application.applicationName,
        MAX_NAME_LENGTH,
        "service bootstrap application name",
        fail,
      ),
      clientId: parseClientId(application.clientId, fail),
      redirectUris: Object.freeze(
        redirectEntries.map((entry) =>
          captureCanonicalHttpsUrl(entry, "service bootstrap redirect URI", fail, true),
        ),
      ),
    }),
    userHandle: boundedText(
      record.userHandle,
      MAX_HANDLE_LENGTH,
      "service bootstrap user handle",
      fail,
    ),
    account,
    ownerValidator,
    chains: Object.freeze(chains),
    sessionSigner: captureSessionSigner(record.sessionSigner, context, fail),
  });
}

export function parseServiceBootstrap(value: unknown): Readonly<ServiceBootstrap> {
  return capturedByProtocol(
    "service_bootstrap_invalid",
    "service bootstrap could not be captured safely",
    () =>
      captureServiceBootstrap(value, new WeakSet(), protocolFailure("service_bootstrap_invalid")),
  );
}
