/**
 * Wallet-owned sessions and owner execution share one durable operation store.
 * The wrapping key and session record must persist before consent. Pending
 * consent occupies this realm until accepted or rejected; close invalidates it.
 * Reload reconstructs the session, Grant and exact operation IDs from stores.
 * It never retries submission. The outer realm owns all raw stores, including
 * cleanup after partial composition; failed closes remain retryable.
 */
import {
  captureDenseArray,
  captureRecord,
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  parseKernelAccountProfile,
} from "@oaath/protocol";
import type { Address } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { OaathCleanupError } from "../cleanup/coordinator.js";
import type { Oaath, OaathStoreConfiguration } from "../create-oaath.js";
import { detectKernelAccountDeployment } from "../kernel/deployment/account.js";
import { kernelV33Deployment } from "../kernel/deployment/v33.js";
import { type EcdsaWalletClient, ecdsaKey } from "../kernel/key/ecdsa.js";
import type { KeyProfile } from "../kernel/types.js";
import { routingAddress } from "../routing/capabilities.js";
import { GrantStore, type OperationStoreAdapter } from "../store.js";
import { captureOaathBinding } from "./binding.js";
import type { OaathChains } from "./chain-descriptors.js";
import type { LocalPermissionAuthorization } from "./connection.js";
import {
  clientCapability,
  clientFail,
  clientFailure,
  exactClientRecord,
  mapClientFailure,
  OaathClientError,
} from "./errors.js";
import { captureChainCapability, type OaathChainCapability } from "./grant-handle.js";
import { deriveOperatorCredentialProfile, deriveOwnerCredentialProfile } from "./key-credential.js";
import {
  createLocalPermissionAuthority,
  type LocalPermissionSign,
  type OaathWalletApprovalReview,
} from "./local-permission.js";
import {
  captureOwnerKey,
  createOwnerRealm,
  type OaathOwnerClient,
  ownerKeyUnsupported,
} from "./owner-realm.js";
import { loadServiceSession, saveServiceSession, serviceSessionKeyId } from "./service-session.js";
import {
  captureSession,
  type OaathSession,
  unsupportedSessionCustody,
} from "./session-credential.js";
import { STORE_NAMES } from "./store-configuration.js";
import { captureStores, type OaathStores, type OwnedStores, openStores } from "./stores.js";

export type OaathApprovalWallet = EcdsaWalletClient & {
  readonly signTypedData: LocalPermissionSign;
};
/**
 * The account's root owner: a connected wallet that approves with one
 * typed-data signature (the ECDSA default), or any `kernelKey(...)` signing
 * profile, such as a raw P-256 key, that signs the same approval digest.
 */
export type OaathApprovalOwner = OaathApprovalWallet | Readonly<KeyProfile>;
export type { OaathWalletApprovalReview } from "./local-permission.js";
/** The account's root owner approves Grants with one signature. */
export interface OaathWalletApprovals {
  readonly kind: "wallet";
  readonly owner: OaathApprovalOwner;
  /** Display the decoded policy before wallet consent. Throw to cancel. */
  readonly onApproval?: (review: Readonly<OaathWalletApprovalReview>) => Promise<void>;
}
/** `createOAAth` options whose Grants the connected wallet approves. */
export interface OaathWalletOptions {
  /** Plain descriptors build the default Cetane ports; custom capabilities override them. */
  readonly chains: OaathChains<OaathChainCapability>;
  readonly account: Address;
  readonly approvals: Readonly<OaathWalletApprovals>;
  readonly session?: Readonly<OaathSession>;
  /**
   * Defaults to `{ kind: "indexeddb" }`, which fails closed outside a browser.
   * `{ kind: "memory" }` is for tests and non-browser development.
   */
  readonly stores?: OaathStores;
  /** Defaults to the actual browser origin; required outside a browser. */
  readonly origin?: string;
  readonly now?: () => number;
}
/** Wallet-approved Grants plus owner execution on the same account. */
export interface OaathWalletApprovalClient extends Oaath, OaathOwnerClient {}

export function createLocalRealm(
  value: unknown,
  compose: (configuration: unknown, authorization: LocalPermissionAuthorization) => Readonly<Oaath>,
): Readonly<OaathWalletApprovalClient> {
  const fail = clientFailure("oaath_client_input_invalid");
  const context = new WeakSet();
  const initial = captureRecord(value, "local configuration", context, fail);
  const config = exactClientRecord(
    initial,
    [
      "account",
      "approvals",
      "chains",
      ...["session", "stores", "origin", "now"].filter((key) => Object.hasOwn(initial, key)),
    ],
    "local configuration",
    new WeakSet(),
  );
  const address = routingAddress(config.account, "local account", fail);
  const initialApprovals = captureRecord(config.approvals, "wallet approvals", context, fail);
  const approvals = exactClientRecord(
    initialApprovals,
    ["kind", "owner", ...(Object.hasOwn(initialApprovals, "onApproval") ? ["onApproval"] : [])],
    "wallet approvals",
    new WeakSet(),
  );
  if (approvals.kind !== "wallet") return fail("wallet approvals kind is required");
  const onApproval =
    approvals.onApproval === undefined
      ? null
      : clientCapability<NonNullable<OaathWalletApprovals["onApproval"]>>(
          approvals.onApproval,
          "local approval display",
        );
  const ownerKey = captureOwnerKey(approvals.owner);
  // A wallet approves through its typed-data prompt; a key profile signs the
  // same digest through its own signing capability.
  const walletApproval = (() => {
    if (Object.hasOwn(approvals.owner as object, "publicMaterial")) return null;
    const owner = approvals.owner as OaathApprovalWallet;
    const wallet = captureRecord(owner, "local wallet", context, fail);
    const walletAccount = captureRecord(wallet.account, "local wallet account", context, fail);
    const signTypedData = clientCapability<LocalPermissionSign>(
      wallet.signTypedData,
      "wallet typed-data signing",
    );
    return Object.freeze({
      signTypedData: signTypedData.bind(owner),
      localWallet: walletAccount.type === "local",
    });
  })();
  const ownerCredential = deriveOwnerCredentialProfile(ownerKey);
  if (ownerCredential === null || ownerCredential.kind === "webauthn") return ownerKeyUnsupported();
  const entries = captureDenseArray(config.chains, "local chains", context, fail);
  if (entries.length < 1 || entries.length > 32) return fail("local mode requires 1 to 32 chains");
  const chains = Object.freeze(entries.map(captureChainCapability));
  if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length)
    return fail("local chains repeat an ID");
  const session = captureSession(config.session, context);
  // Wallet approvals have no service to serve remote custody.
  if (session.custody !== null && session.custody !== "browser") {
    unsupportedSessionCustody("wallet approvals support browser session custody only");
  }
  const suppliedSession = session.supplied;
  const origin =
    config.origin ?? (globalThis as { location?: { origin?: string } }).location?.origin;
  if (typeof origin !== "string")
    return fail("local mode requires a browser origin or an explicit origin");
  const now =
    config.now === undefined
      ? () => Math.floor(Date.now() / 1000)
      : clientCapability<() => number>(config.now, "local clock");
  // The account's deployment is detected on every configured chain, never
  // assumed. Chains that disagree cannot share one account profile.
  async function detectedAccountProfile() {
    let kernelVersion: string | undefined;
    for (const chain of chains) {
      const deployment = await detectKernelAccountDeployment({
        chainId: chain.chainId,
        address,
        reads: chain.reads,
      });
      if (kernelVersion !== undefined && deployment.kernelVersion !== kernelVersion)
        return clientFail(
          "oaath_client_state_conflict",
          "configured chains run different Kernel deployments",
          "local_account_deployment_mismatch",
        );
      kernelVersion = deployment.kernelVersion;
    }
    return parseKernelAccountProfile({
      version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
      kind: "kernel",
      kernelVersion,
      address,
      entryPoint: { version: kernelVersion === "0.4.0" ? "0.9" : "0.7" },
      ownerCredential,
    });
  }
  const identityInput = {
    issuer: origin,
    applicationId: "local",
    applicationName: "Local OAAth",
    clientId: "local",
    origin,
    redirectUri: `${origin}/oaath/local`,
    userHandle: ownerKey.publicMaterial,
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "local",
      workspaceKind: "personal",
      accountId: address,
    } as const,
  };
  const storeSetting = captureStores(config.stores, STORE_NAMES, context);
  let stores: Readonly<OaathStoreConfiguration> | undefined;
  let storeOwner: Readonly<OwnedStores<(typeof STORE_NAMES)[number]>> | undefined;
  let openingStores: Promise<Readonly<OaathStoreConfiguration>> | undefined;
  async function storage() {
    if (stores) return stores;
    openingStores ??= openStores(storeSetting, STORE_NAMES).then(
      (owner) => {
        storeOwner = owner;
        stores = owner.stores;
        return stores;
      },
      (error) => {
        openingStores = undefined;
        throw error;
      },
    );
    return openingStores;
  }
  const operations: OperationStoreAdapter = {
    get: async (key) => (await storage()).operations.get(key),
    getArchived: async (key) => (await storage()).operations.getArchived(key),
    list: async (scope) => (await storage()).operations.list(scope),
    compareAndSwap: async (input) => (await storage()).operations.compareAndSwap(input),
    close: async () => undefined,
  };
  // The shared journal is an override, so the owner realm opens no backend.
  const ownerClient = createOwnerRealm({
    chains,
    account: address,
    stores: { kind: "memory", operations },
  });
  let inner: Readonly<Oaath> | undefined;
  let authority: ReturnType<typeof createLocalPermissionAuthority> | undefined;
  let composing: Promise<Readonly<Oaath>> | undefined;
  let closeRequested = false;
  let closed = false;
  let closing: Promise<void> | undefined;
  const closedStores = new Set<object>();
  function assertOpen() {
    if (closeRequested) clientFail("oaath_client_closed", "local client is closed");
  }
  async function realm() {
    if (inner) return inner;
    composing ??= (async () => {
      const bindingInput = { ...identityInput, account: await detectedAccountProfile() };
      // Capture public identity before opening storage or invoking a wallet.
      // No session exists yet, so a fixed placeholder fills the operator slot;
      // only the identity fields below are read from this binding.
      const baseBinding = captureOaathBinding({
        ...bindingInput,
        deviceId: "local",
        operatorCredential: {
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa",
          address: `0x${"00".repeat(19)}01`,
        },
      });
      const owned = await storage();
      const bootstrap = {
        application: bindingInput,
        userHandle: bindingInput.userHandle,
        context: baseBinding.context,
        account: baseBinding.account,
      };
      const continuity = {
        stores: owned,
        url: baseBinding.issuer.url,
        origin: baseBinding.client.origin,
        bootstrap,
      };
      const { deviceId, sessionKey, localKeyIds } =
        suppliedSession === null
          ? await generatedSession(continuity)
          : { ...suppliedSession, localKeyIds: [] };
      const binding = {
        ...bindingInput,
        deviceId,
        operatorCredential: deriveOperatorCredentialProfile(sessionKey),
      };
      authority = createLocalPermissionAuthority({
        binding: captureOaathBinding(binding),
        owner: ownerKey,
        session: sessionKey,
        grants: new GrantStore({ ...owned.grants, close: async () => undefined }),
        chains,
        walletApproval,
        onApproval,
        now,
      });
      // This realm owns raw stores. Child realms close only their own handles.
      const borrowed = Object.fromEntries(
        Object.entries(owned).map(([name, port]) => [
          name,
          Object.freeze({ ...port, close: async () => undefined }),
        ]),
      );
      inner = compose(
        {
          binding,
          stores: borrowed,
          chains,
          invalidation: authority.invalidation,
          signing: { owner: ownerKey, session: sessionKey },
          localKeyIds,
          now,
        },
        authority.approve,
      );
      return inner;
    })().catch((error) => {
      composing = undefined;
      return mapClientFailure(error, "local realm could not be opened");
    });
    return composing;
  }
  async function generatedSession(continuity: Parameters<typeof loadServiceSession>[0]) {
    let session = await loadServiceSession(continuity);
    if (session === null) {
      session = Object.freeze({
        deviceId: crypto.randomUUID(),
        privateKey: generatePrivateKey(),
      });
      // A local session must survive before asking the owner for authority.
      await saveServiceSession({ ...continuity, session, now });
    }
    return {
      deviceId: session.deviceId,
      sessionKey: ecdsaKey({
        account: privateKeyToAccount(session.privateKey),
        validator: kernelV33Deployment(chains[0]!.chainId).ecdsaValidator,
      }),
      localKeyIds: [serviceSessionKeyId(continuity.url, continuity.origin, continuity.bootstrap)],
    };
  }
  async function close() {
    if (closed) return;
    closeRequested = true;
    authority?.close();
    closing ??= (async () => {
      await composing?.catch(() => undefined);
      authority?.close();
      const failures: unknown[] = [];
      for (const child of [ownerClient, inner])
        if (child) await child.close().catch((error) => failures.push(error));
      for (const port of Object.values(stores ?? storeSetting.overrides)) {
        if (closedStores.has(port)) continue;
        await Promise.resolve()
          .then(() => port.close())
          .then(() => closedStores.add(port))
          .catch((error) => failures.push(error));
      }
      if (failures.length)
        return clientFail("oaath_client_internal", "local resources could not all be closed");
      await storeOwner?.close();
      closed = true;
    })().finally(() => {
      closing = undefined;
    });
    return closing;
  }
  return Object.freeze({
    get binding() {
      if (!inner)
        return clientFail(
          "oaath_client_input_invalid",
          "connect before reading the local session binding",
        );
      return inner.binding;
    },
    async connect() {
      assertOpen();
      const client = await realm();
      assertOpen();
      return client.connect();
    },
    account(value: Address) {
      assertOpen();
      if (routingAddress(value, "local account", fail) !== address)
        return clientFail("oaath_client_state_conflict", "local realm belongs to another account");
      return ownerClient.account(address);
    },
    async disconnect(grant) {
      const client = await realm();
      let result: Awaited<ReturnType<Oaath["disconnect"]>>;
      try {
        result = await client.disconnect(grant);
      } catch (error) {
        await close().catch(() => undefined);
        throw error;
      }
      try {
        await close();
        return result;
      } catch {
        throw new OaathCleanupError(
          "cleanup_incomplete",
          "local cleanup left resources open",
          ["close"],
          [
            ...result.failures,
            Object.freeze({
              effect: "close" as const,
              error: new OaathClientError(
                "oaath_client_internal",
                "local resources could not all be closed",
              ),
            }),
          ],
        );
      }
    },
    close,
  } satisfies OaathWalletApprovalClient);
}
