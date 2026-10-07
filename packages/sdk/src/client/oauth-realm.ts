/**
 * OAuth-approved Grants: the dapp's session key, reviewed and root-approved in
 * the issuer's portal popup.
 *
 * ```text
 * createOAAth({ chains, approvals: { kind: "oauth", issuer, clientId, redirectUri } })
 * connect()            nothing remote; the account is chosen in the portal
 * requestPermission()  popup opens inside the click
 *                      the frontend session key (non-extractable, persisted
 *                      before any request) becomes authorization_details.signer
 *                      PAR oaath_grant -> portal: signer, account, review, the
 *                      account root signs the replayable install -> token
 *                      the returned request must be exactly ours (signer,
 *                      client, origin, device, policy, expiry) for the
 *                      account the id_token names; only then is anything stored
 *                      the realm binds to that account and applies
 *                      {request, decision + installApproval} through the
 *                      ordinary connection: the Grant handle's first sendCalls
 *                      installs the permission in enable mode
 * resume()             the stored binding pointer rebuilds the realm; the
 *                      Grant and operations come from the existing stores
 * ```
 *
 * A member's request waits for the account root: the popup returns a code
 * whose token answers `authorization_pending`. `requestPermission` then
 * journals the code, its PKCE verifier and nonce and the expected request, and
 * returns `{ state: "pending" }`. `redeemPending()` makes one token request
 * per call, never a new authorization, and adopts the Grant once the root
 * approves. One pending request at a time; a rejection, an expired or spent
 * code, or the request's expiry clears the journal.
 *
 * The issuer is trusted for nothing: the decision carries the root's own
 * replayable install signature, which Kernel verifies on chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type PermissionRequest,
  parseGrantPolicy,
  parsePermissionRequest,
} from "@oaath/protocol";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { encodeAbiParameters, keccak256 } from "cetane/utils";
import type { Oaath, OaathStoreConfiguration } from "../create-oaath.js";
import { ECDSA_VALIDATOR } from "../kernel/deployment/v33.js";
import { credentialKey } from "../kernel/key/credential.js";
import { ecdsaKey } from "../kernel/key/ecdsa.js";
import { GrantStore } from "../store.js";
import { captureOaathBinding } from "./binding.js";
import type { OaathChains } from "./chain-descriptors.js";
import {
  adoptApprovedPermission,
  capturePermissionInput,
  type LocalPermissionAuthorization,
  type OaathConnection,
} from "./connection.js";
import {
  clientCapability,
  clientFail,
  clientFailure,
  exactClientRecord,
  mapClientFailure,
  OaathClientError,
} from "./errors.js";
import {
  captureChainCapability,
  type OaathChainCapability,
  type OaathGrantHandle,
} from "./grant-handle.js";
import { deriveOperatorCredentialProfile } from "./key-credential.js";
import { localAdmissionInvalidation } from "./local-permission.js";
import {
  authorizeThroughPopup,
  authorizeWithLauncher,
  type OaathAuthorizationLauncher,
  type OaathCodeExchange,
  type OaathLogin,
  openAuthorizationPopup,
  redeemAuthorizationCode,
} from "./oauth-login.js";
import { loadServiceSession, saveServiceSession, serviceSessionKeyId } from "./service-session.js";
import { STORE_NAMES } from "./store-configuration.js";
import { captureStores, type OaathStores, type OwnedStores, openStores } from "./stores.js";

const POINTER_VERSION = "oaath.oauth-realm-binding/v1" as const;
const POINTER_DOMAIN = "@oaath/sdk:oauth-realm-binding" as const;
const PENDING_VERSION = "oaath.oauth-pending-grant/v1" as const;
const PENDING_DOMAIN = "@oaath/sdk:oauth-pending-grant" as const;

/** A requested Grant the account root has not decided yet. */
export interface OaathPendingPermission {
  readonly state: "pending";
  /** The issuer's id for the pushed request. */
  readonly requestId: string;
  /** The request's expiry (unix seconds); the journal is dropped after it. */
  readonly expiresAt: number;
}

/** The OAuth realm's connection: a request may wait for the account root. */
export interface OaathOAuthConnection extends Omit<OaathConnection, "requestPermission"> {
  readonly requestPermission: (
    input: unknown,
  ) => Promise<Readonly<OaathGrantHandle> | Readonly<OaathPendingPermission>>;
  /**
   * One token request for the journaled pending Grant: the Grant once the root
   * approved, the same pending result while it has not, or null when nothing is
   * pending. A rejection fails with `oaath_client_permission_rejected`.
   */
  readonly redeemPending: () => Promise<
    Readonly<OaathGrantHandle> | Readonly<OaathPendingPermission> | null
  >;
}

/** `createOAAth` with OAuth approvals. */
export interface OaathOAuthClient extends Omit<Oaath, "connect"> {
  readonly connect: () => Promise<Readonly<OaathOAuthConnection>>;
}

interface ExpectedGrant {
  readonly policy: unknown;
  readonly expiresAt: number;
  readonly operatorCredential: unknown;
  readonly deviceId: string;
}

/** The issuer's portal approves Grants for the dapp's own session key. */
export interface OaathOAuthApprovals {
  readonly kind: "oauth";
  /** The OAAth issuer, for example `https://oaath.taek.tech` (no trailing slash). */
  readonly issuer: string;
  /** The client registered with the issuer (`POST /oauth/clients`). */
  readonly clientId: string;
  /** A registered redirect URI on this page's origin that runs `completeOAAthLogin`. */
  readonly redirectUri: string;
  /** How long the user may take in the popup. Defaults to five minutes. */
  readonly timeoutMs?: number;
  /**
   * Opens the portal somewhere other than a popup and resolves with the
   * redirect URL, e.g. `chrome.identity.launchWebAuthFlow` in an extension.
   * `redirectUri` may then be off this page's origin.
   */
  readonly launch?: OaathAuthorizationLauncher;
}

/** `createOAAth` options whose Grants the account root approves in the portal. */
export interface OaathOAuthOptions {
  readonly chains: OaathChains<OaathChainCapability>;
  readonly approvals: Readonly<OaathOAuthApprovals>;
  /** Defaults to `{ kind: "indexeddb" }`; `{ kind: "memory" }` for tests. */
  readonly stores?: OaathStores;
  /** Defaults to the actual browser origin. */
  readonly origin?: string;
  readonly now?: () => number;
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function createOAuthRealm(
  value: unknown,
  compose: (configuration: unknown, authorization: LocalPermissionAuthorization) => Readonly<Oaath>,
): Readonly<OaathOAuthClient> {
  const fail = clientFailure("oaath_client_input_invalid");
  const context: CaptureContext = new WeakSet();
  const initial = captureRecord(value, "OAuth configuration", context, fail);
  const config = exactClientRecord(
    initial,
    [
      "approvals",
      "chains",
      ...["stores", "origin", "now"].filter((key) => Object.hasOwn(initial, key)),
    ],
    "OAuth configuration",
    new WeakSet(),
  );
  const initialApprovals = captureRecord(config.approvals, "OAuth approvals", context, fail);
  const approvals = exactClientRecord(
    initialApprovals,
    [
      "kind",
      "issuer",
      "clientId",
      "redirectUri",
      ...["timeoutMs", "launch"].filter((key) => Object.hasOwn(initialApprovals, key)),
    ],
    "OAuth approvals",
    new WeakSet(),
  );
  if (approvals.kind !== "oauth") return fail("OAuth approvals kind is required");
  const launch =
    approvals.launch === undefined
      ? null
      : clientCapability<OaathAuthorizationLauncher>(approvals.launch, "OAuth launcher");
  const popupOptions = Object.freeze({
    issuer: approvals.issuer as string,
    clientId: approvals.clientId as string,
    redirectUri: approvals.redirectUri as string,
    ...(approvals.timeoutMs === undefined ? {} : { timeoutMs: approvals.timeoutMs as number }),
  });
  if (
    typeof popupOptions.issuer !== "string" ||
    typeof popupOptions.clientId !== "string" ||
    typeof popupOptions.redirectUri !== "string"
  )
    return fail("OAuth approvals need an issuer, clientId, and redirectUri");
  const entries = captureDenseArray(config.chains, "OAuth chains", context, fail);
  if (entries.length < 1 || entries.length > 32) return fail("OAuth needs 1 to 32 chains");
  const chains = Object.freeze(entries.map(captureChainCapability));
  if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length)
    return fail("OAuth chains repeat an ID");
  const configuredOrigin =
    config.origin ?? (globalThis as { location?: { origin?: string } }).location?.origin;
  if (typeof configuredOrigin !== "string")
    return fail("OAuth needs a browser origin or an explicit origin");
  const origin: string = configuredOrigin;
  const now =
    config.now === undefined
      ? () => Math.floor(Date.now() / 1000)
      : clientCapability<() => number>(config.now, "OAuth clock");
  const storeSetting = captureStores(config.stores, STORE_NAMES, context);

  // One frontend session key per issuer, client, and origin: it exists before
  // any request, so the request names it and only this browser can use it.
  const sessionScope = {
    application: { applicationId: popupOptions.clientId, clientId: popupOptions.clientId },
    userHandle: POINTER_DOMAIN,
    context: null,
    account: null,
  } as unknown as Parameters<typeof loadServiceSession>[0]["bootstrap"];
  const pointerId = keccak256(
    encodeAbiParameters(
      [{ type: "string" }, { type: "string" }, { type: "string" }, { type: "string" }],
      [POINTER_DOMAIN, popupOptions.issuer, origin, popupOptions.clientId],
    ),
  );
  const pendingId = keccak256(
    encodeAbiParameters(
      [{ type: "string" }, { type: "string" }, { type: "string" }, { type: "string" }],
      [PENDING_DOMAIN, popupOptions.issuer, origin, popupOptions.clientId],
    ),
  );

  let stores: Readonly<OaathStoreConfiguration> | undefined;
  let storeOwner: Readonly<OwnedStores<(typeof STORE_NAMES)[number]>> | undefined;
  let opening: Promise<Readonly<OaathStoreConfiguration>> | undefined;
  const realms = new Map<string, Readonly<Oaath>>();
  const connections = new Map<string, Readonly<OaathConnection>>();
  let bound: Readonly<Oaath> | undefined;
  let closeRequested = false;
  let closing: Promise<void> | undefined;

  function assertOpen() {
    if (closeRequested) clientFail("oaath_client_closed", "OAuth client is closed");
  }

  async function storage() {
    if (stores) return stores;
    opening ??= openStores(storeSetting, STORE_NAMES).then(
      (owner) => {
        storeOwner = owner;
        stores = owner.stores;
        return stores;
      },
      (error) => {
        opening = undefined;
        throw error;
      },
    );
    return opening;
  }

  async function session() {
    const continuity = {
      stores: await storage(),
      url: popupOptions.issuer,
      origin,
      bootstrap: sessionScope,
    };
    let persisted = await loadServiceSession(continuity);
    if (persisted === null) {
      persisted = Object.freeze({
        deviceId: crypto.randomUUID(),
        privateKey: generatePrivateKey(),
      });
      // The session must survive before the owner is asked for authority.
      await saveServiceSession({ ...continuity, session: persisted, now });
    }
    const key = ecdsaKey({
      account: privateKeyToAccount(persisted.privateKey),
      validator: ECDSA_VALIDATOR,
    });
    const operatorCredential = deriveOperatorCredentialProfile(key);
    if (operatorCredential === null)
      return clientFail("oaath_client_internal", "the session key has no credential profile");
    return { deviceId: persisted.deviceId, key, operatorCredential };
  }

  /** The realm for the account one approved request names. */
  async function realmFor(request: Readonly<PermissionRequest>) {
    const owned = await storage();
    const { key, operatorCredential, deviceId } = await session();
    if (
      !same(request.operatorCredential, operatorCredential) ||
      request.application.deviceId !== deviceId
    )
      return clientFail(
        "oaath_client_state_conflict",
        "the stored Grant names another session key",
        "oauth_session_mismatch",
      );
    const bindingInput = {
      issuer: popupOptions.issuer,
      applicationId: request.application.applicationId,
      applicationName: popupOptions.clientId,
      clientId: popupOptions.clientId,
      origin,
      redirectUri: popupOptions.redirectUri,
      deviceId,
      userHandle: request.context.accountId,
      context: request.context,
      account: request.logicalAccount,
      operatorCredential,
    };
    const binding = captureOaathBinding(bindingInput);
    const existing = realms.get(binding.bindingId);
    if (existing) return existing;
    const owner = request.logicalAccount.ownerCredential;
    const borrowed = Object.fromEntries(
      Object.entries(owned).map(([name, port]) => [
        name,
        Object.freeze({ ...port, close: async () => undefined }),
      ]),
    );
    const realm = compose(
      {
        binding: bindingInput,
        stores: borrowed,
        chains,
        invalidation: localAdmissionInvalidation({
          binding,
          grants: new GrantStore({ ...owned.grants, close: async () => undefined }),
          now,
        }),
        signing: {
          owner: credentialKey({
            credential: owner,
            validator: owner.kind === "ecdsa" ? ECDSA_VALIDATOR : null,
          }),
          session: key,
        },
        localKeyIds: [serviceSessionKeyId(popupOptions.issuer, origin, sessionScope)],
        now,
      },
      // Approvals arrive through the popup and are adopted, never re-asked.
      async () => clientFail("oaath_client_internal", "OAuth approvals are obtained in the portal"),
    );
    realms.set(binding.bindingId, realm);
    return realm;
  }

  async function connectionFor(request: Readonly<PermissionRequest>) {
    const realm = await realmFor(request);
    bound = realm;
    const key = realm.binding.bindingId;
    let connection = connections.get(key);
    if (!connection) {
      connection = await realm.connect();
      connections.set(key, connection);
    }
    return connection;
  }

  async function readPointer(): Promise<Readonly<PermissionRequest> | null> {
    const raw = await (await storage()).context.read(pointerId);
    if (raw === undefined || raw === null) return null;
    try {
      const record = exactClientRecord(
        raw,
        ["version", "bindingId", "request"],
        "OAuth binding pointer",
        new WeakSet(),
      );
      if (record.version !== POINTER_VERSION || record.bindingId !== pointerId) throw new Error();
      return parsePermissionRequest(record.request);
    } catch {
      // Unreadable is not absent.
      return clientFail(
        "oaath_client_state_conflict",
        "the stored OAuth binding is unreadable",
        "oauth_binding_unreadable",
      );
    }
  }

  async function writePointer(request: Readonly<PermissionRequest>) {
    await (await storage()).context.write(
      Object.freeze({ version: POINTER_VERSION, bindingId: pointerId, request }) as never,
    );
  }

  async function readPending(): Promise<Readonly<{
    exchange: OaathCodeExchange;
    expected: ExpectedGrant;
  }> | null> {
    const raw = await (await storage()).context.read(pendingId);
    if (raw === undefined || raw === null) return null;
    try {
      const record = exactClientRecord(
        raw,
        ["version", "bindingId", "exchange", "expected"],
        "OAuth pending grant",
        new WeakSet(),
      );
      const exchange = exactClientRecord(
        record.exchange,
        ["requestId", "code", "verifier", "nonce"],
        "OAuth pending exchange",
        new WeakSet(),
      );
      const expected = exactClientRecord(
        record.expected,
        ["policy", "expiresAt", "operatorCredential", "deviceId"],
        "OAuth pending expectation",
        new WeakSet(),
      );
      if (
        record.version !== PENDING_VERSION ||
        record.bindingId !== pendingId ||
        [exchange.requestId, exchange.code, exchange.verifier, exchange.nonce].some(
          (field) => typeof field !== "string",
        ) ||
        !Number.isSafeInteger(expected.expiresAt) ||
        typeof expected.deviceId !== "string"
      )
        throw new Error();
      return {
        exchange: exchange as unknown as OaathCodeExchange,
        expected: expected as unknown as ExpectedGrant,
      };
    } catch {
      // Unreadable is not absent.
      return clientFail(
        "oaath_client_state_conflict",
        "the stored pending OAuth grant is unreadable",
        "oauth_pending_unreadable",
      );
    }
  }

  async function writePending(exchange: OaathCodeExchange, expected: ExpectedGrant) {
    await (await storage()).context.write(
      Object.freeze({
        version: PENDING_VERSION,
        bindingId: pendingId,
        exchange,
        expected,
      }) as never,
    );
  }

  async function clearPending() {
    await (await storage()).context.clear(pendingId);
  }

  function pending(exchange: OaathCodeExchange, expected: ExpectedGrant) {
    return Object.freeze({
      state: "pending" as const,
      requestId: exchange.requestId,
      expiresAt: expected.expiresAt,
    });
  }

  /** Verifies a released Grant and adopts it through the account's connection. */
  async function adopt(
    token: Readonly<Record<string, unknown>>,
    login: Readonly<OaathLogin>,
    expected: ExpectedGrant,
  ) {
    const { request, artifact } = verifyGrant(token, login, expected);
    assertOpen();
    const connection = await connectionFor(request);
    await writePointer(request);
    return adoptApprovedPermission(connection, request, artifact);
  }

  /** The approved request must be exactly the one this browser asked for. */
  function verifyGrant(
    token: Readonly<Record<string, unknown>>,
    login: Readonly<OaathLogin>,
    expected: ExpectedGrant,
  ) {
    const mismatch = (): never =>
      clientFail(
        "oaath_client_state_conflict",
        "the approved Grant is not the one this application requested",
        "oauth_grant_mismatch",
      );
    const details = token.authorization_details;
    if (!Array.isArray(details) || details.length !== 1) return mismatch();
    const detail = exactClientRecord(
      details[0],
      ["type", "grant_id", "permission_request", "decision", "enable"],
      "OAuth grant detail",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    let request: Readonly<PermissionRequest>;
    try {
      request = parsePermissionRequest(detail.permission_request);
      parseGrantPolicy(request.policy);
    } catch (error) {
      return mapClientFailure(error, "the approved permission request is invalid");
    }
    if (
      detail.type !== "oaath_grant" ||
      detail.grant_id !== request.requestId ||
      !same(request.operatorCredential, expected.operatorCredential) ||
      !same(request.application, {
        applicationId: popupOptions.clientId,
        clientId: popupOptions.clientId,
        origin,
        deviceId: expected.deviceId,
      }) ||
      !same(request.policy, expected.policy) ||
      request.expiresAt !== expected.expiresAt ||
      request.chainScope !== "all" ||
      request.sessionSigner !== null ||
      !same(request.logicalAccount, login.accountProfile) ||
      request.context.accountId !== login.account
    )
      return mismatch();
    const enable = captureRecord(detail.enable, "OAuth grant enable", new WeakSet(), mismatch);
    // The root's install must name the very account the user signed in to.
    if (enable.account !== login.account) return mismatch();
    const decision = captureRecord(
      detail.decision,
      "OAuth grant decision",
      new WeakSet(),
      mismatch,
    );
    return { request, artifact: { ...decision, installApproval: enable } };
  }

  async function requestPermission(
    input: unknown,
  ): Promise<Readonly<OaathGrantHandle> | Readonly<OaathPendingPermission>> {
    assertOpen();
    // Open inside the user's gesture, before anything is awaited.
    const popup = launch ? null : openAuthorizationPopup();
    try {
      const captured = capturePermissionInput(input, now());
      if ((await readPending()) !== null)
        return clientFail(
          "oaath_client_state_conflict",
          "a requested Grant still awaits the account root; redeem it first",
          "oauth_permission_pending",
        );
      const { deviceId, operatorCredential } = await session();
      const detail = {
        type: "oaath_grant",
        signer: operatorCredential,
        policy: captured.policy,
        chains: chains.map((chain) => chain.chainId),
        expires_at: captured.expiresAt,
        device_id: deviceId,
      };
      const expected: ExpectedGrant = {
        policy: captured.policy,
        expiresAt: captured.expiresAt,
        operatorCredential,
        deviceId,
      };
      const extra = { authorization_details: JSON.stringify([detail]) };
      const { exchange, released } = popup
        ? await authorizeThroughPopup(popup, popupOptions, extra)
        : await authorizeWithLauncher(launch as OaathAuthorizationLauncher, popupOptions, extra);
      if (released === null) {
        await writePending(exchange, expected);
        return pending(exchange, expected);
      }
      return await adopt(released.token, released.login, expected);
    } finally {
      popup?.close();
    }
  }

  async function redeemPending(): Promise<
    Readonly<OaathGrantHandle> | Readonly<OaathPendingPermission> | null
  > {
    assertOpen();
    const journal = await readPending();
    if (journal === null) return null;
    const { exchange, expected } = journal;
    if (expected.expiresAt <= now()) {
      await clearPending();
      return null;
    }
    let released: Awaited<ReturnType<typeof redeemAuthorizationCode>>;
    try {
      released = await redeemAuthorizationCode(popupOptions, exchange);
    } catch (error) {
      // A rejected, expired or spent code never redeems; anything else may retry.
      if (
        error instanceof OaathClientError &&
        (error.code === "oaath_client_permission_rejected" ||
          (error.code === "oaath_client_issuer_rejected" && error.source === "invalid_grant"))
      )
        await clearPending();
      throw error;
    }
    if (released === null) return pending(exchange, expected);
    try {
      return await adopt(released.token, released.login, expected);
    } finally {
      // The code is spent once released, whatever adoption concluded.
      await clearPending();
    }
  }

  async function resume(): Promise<Readonly<OaathGrantHandle> | null> {
    assertOpen();
    const request = await readPointer();
    if (request === null) return null;
    return (await connectionFor(request)).resume();
  }

  const facade: Readonly<OaathOAuthConnection> = Object.freeze({
    get binding() {
      if (!bound)
        return clientFail("oaath_client_input_invalid", "request or resume a permission first");
      return bound.binding;
    },
    requestPermission,
    resume,
    redeemPending,
    async signOut() {
      for (const connection of connections.values()) await connection.signOut();
    },
    async close() {
      for (const connection of connections.values()) await connection.close();
      connections.clear();
    },
  });

  async function close() {
    closeRequested = true;
    closing ??= (async () => {
      await opening?.catch(() => undefined);
      const failures: unknown[] = [];
      for (const realm of realms.values())
        await realm.close().catch((error: unknown) => failures.push(error));
      if (failures.length)
        return clientFail("oaath_client_internal", "OAuth resources could not all be closed");
      await storeOwner?.close();
    })().finally(() => {
      closing = undefined;
    });
    return closing;
  }

  return Object.freeze({
    get binding() {
      return facade.binding;
    },
    async connect() {
      assertOpen();
      return facade;
    },
    async disconnect(grant: Readonly<OaathGrantHandle> | null) {
      if (!bound) {
        await close();
        return Object.freeze({
          cleanupId: pointerId,
          completed: Object.freeze(["close" as const]),
          unfinished: Object.freeze([]),
          failures: Object.freeze([]),
        });
      }
      const result = await bound.disconnect(grant);
      await close();
      return result;
    },
    close,
  } satisfies OaathOAuthClient);
}
