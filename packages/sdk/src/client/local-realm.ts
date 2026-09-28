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
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  parseKernelAccountProfile,
} from "@oaath/protocol";
import type { Address } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { OaathCleanupError } from "../cleanup/coordinator.js";
import type { Oaath, OaathStoreConfiguration } from "../create-oaath.js";
import { kernelV33Deployment } from "../kernel/deployment/v33.js";
import { type EcdsaWalletClient, ecdsaKey, ecdsaWalletKey } from "../kernel/key/ecdsa.js";
import { routingAddress } from "../routing/capabilities.js";
import { GrantStore, type OperationStoreAdapter } from "../store.js";
import { captureOaathBinding } from "./binding.js";
import { defaultStores, type OwnedDefaultStores } from "./default-stores.js";
import {
  clientCapability,
  clientFail,
  clientFailure,
  exactClientRecord,
  mapClientFailure,
  OaathClientError,
} from "./errors.js";
import { captureChainCapability, type OaathChainCapability } from "./grant-handle.js";
import { createLocalPermissionAuthority, type LocalPermissionSign } from "./local-permission.js";
import { createOwnerRealm, type OaathOwnerClient } from "./owner-realm.js";
import { loadServiceSession, saveServiceSession, serviceSessionKeyId } from "./service-session.js";
import { captureStoreConfiguration } from "./store-configuration.js";

export type OaathLocalWallet = EcdsaWalletClient & { readonly signTypedData: LocalPermissionSign };
export interface OaathLocalConfiguration {
  readonly mode: "local";
  readonly account: Readonly<{ kind: "existing"; address: Address }>;
  readonly owner: OaathLocalWallet;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  /** Browser IndexedDB by default. Non-browser callers supply durable stores. */
  readonly stores?: Readonly<OaathStoreConfiguration>;
  /** Defaults to the actual browser origin; required outside a browser. */
  readonly origin?: string;
  readonly now?: () => number;
}
export interface OaathLocalClient extends Oaath, OaathOwnerClient {}

export function createLocalRealm(
  value: unknown,
  compose: (configuration: unknown) => Readonly<Oaath>,
): Readonly<OaathLocalClient> {
  const fail = clientFailure("oaath_client_input_invalid");
  const context = new WeakSet();
  const initial = captureRecord(value, "local configuration", context, fail);
  const config = exactClientRecord(
    initial,
    [
      "mode",
      "account",
      "owner",
      "chains",
      ...["stores", "origin", "now"].filter((key) => Object.hasOwn(initial, key)),
    ],
    "local configuration",
    new WeakSet(),
  );
  const requested = exactClientRecord(
    config.account,
    ["kind", "address"],
    "existing account",
    context,
  );
  if (requested.kind !== "existing") return fail("local mode requires an existing account");
  const address = routingAddress(requested.address, "local account", fail);
  const wallet = captureRecord(config.owner, "local wallet", context, fail);
  const walletAccount = captureRecord(wallet.account, "local wallet account", context, fail);
  const signTypedData = clientCapability<LocalPermissionSign>(
    wallet.signTypedData,
    "wallet typed-data signing",
  );
  const entries = captureDenseArray(config.chains, "local chains", context, fail);
  if (entries.length < 1 || entries.length > 32) return fail("local mode requires 1 to 32 chains");
  const chains = Object.freeze(entries.map(captureChainCapability));
  if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length)
    return fail("local chains repeat an ID");
  const ownerKey = ecdsaWalletKey({
    wallet: config.owner as OaathLocalWallet,
    validator: kernelV33Deployment(chains[0]!.chainId).ecdsaValidator,
  });
  const account = parseKernelAccountProfile({
    version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    kernelVersion: "0.3.3",
    address,
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: ownerKey.publicMaterial,
    },
  });
  const origin =
    config.origin ?? (globalThis as { location?: { origin?: string } }).location?.origin;
  if (typeof origin !== "string")
    return fail("local mode requires a browser origin or an explicit origin");
  const now =
    config.now === undefined
      ? () => Math.floor(Date.now() / 1000)
      : clientCapability<() => number>(config.now, "local clock");
  const bindingInput = {
    issuer: `${origin}/.oaath/local`,
    applicationId: "local",
    applicationName: "Local OAAth",
    clientId: "local",
    origin,
    redirectUri: `${origin}/.oaath/local/callback`,
    userHandle: ownerKey.publicMaterial,
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "local",
      workspaceKind: "personal",
      accountId: address,
    } as const,
    account,
  };
  // Capture public identity before opening storage or invoking a wallet.
  const baseBinding = captureOaathBinding({
    ...bindingInput,
    deviceId: "local",
    operatorCredential: {
      version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: ownerKey.publicMaterial,
    },
  });
  let stores = config.stores === undefined ? undefined : captureStoreConfiguration(config.stores);
  let storeOwner: Readonly<OwnedDefaultStores> | undefined;
  let openingStores: Promise<Readonly<OaathStoreConfiguration>> | undefined;
  async function storage() {
    if (stores) return stores;
    if (typeof indexedDB === "undefined")
      return clientFail(
        "oaath_client_store_unavailable",
        "local mode requires IndexedDB or explicit stores",
      );
    openingStores ??= defaultStores().then((owner) => {
      storeOwner = owner;
      stores = owner.stores;
      return stores;
    });
    return openingStores;
  }
  const operations: OperationStoreAdapter = {
    get: async (key) => (await storage()).operations.get(key),
    getArchived: async (key) => (await storage()).operations.getArchived(key),
    compareAndSwap: async (input) => (await storage()).operations.compareAndSwap(input),
    close: async () => undefined,
  };
  const ownerClient = createOwnerRealm({ mode: "owner", chains, operations });
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
      let session = await loadServiceSession(continuity);
      if (session === null) {
        session = Object.freeze({
          deviceId: crypto.randomUUID(),
          privateKey: generatePrivateKey(),
        });
        // A local session must survive before asking the owner for authority.
        await saveServiceSession({ ...continuity, session, now });
      }
      const sessionAccount = privateKeyToAccount(session.privateKey);
      const sessionKey = ecdsaKey({
        account: sessionAccount,
        validator: kernelV33Deployment(chains[0]!.chainId).ecdsaValidator,
      });
      const binding = {
        ...bindingInput,
        deviceId: session.deviceId,
        operatorCredential: {
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa",
          address: sessionAccount.address.toLowerCase(),
        },
      };
      authority = createLocalPermissionAuthority({
        binding: captureOaathBinding(binding),
        owner: ownerKey,
        session: sessionKey,
        grants: new GrantStore({ ...owned.grants, close: async () => undefined }),
        chains,
        signTypedData: signTypedData.bind(config.owner),
        localWallet: walletAccount.type === "local",
        now,
      });
      // This realm owns raw stores. Child realms close only their own handles.
      const borrowed = Object.fromEntries(
        Object.entries(owned).map(([name, port]) => [
          name,
          Object.freeze({ ...port, close: async () => undefined }),
        ]),
      );
      inner = compose({
        binding,
        issuer: authority.issuer,
        authorization: authority.authorization,
        stores: borrowed,
        chains,
        invalidation: authority.invalidation,
        signing: { owner: ownerKey, session: sessionKey },
        localKeyIds: [serviceSessionKeyId(continuity.url, continuity.origin, bootstrap)],
        now,
      });
      return inner;
    })().catch((error) => {
      composing = undefined;
      return mapClientFailure(error, "local realm could not be opened");
    });
    return composing;
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
      for (const port of Object.values(stores ?? {})) {
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
  } satisfies OaathLocalClient);
}
