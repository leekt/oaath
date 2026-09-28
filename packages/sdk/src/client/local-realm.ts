/** Connected ECDSA owner approval and browser custody without a relay. */
import {
  captureDenseArray,
  captureRecord,
  type GrantPolicy,
  hashPermissionRequest,
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  type PermissionRequest,
  parseClientBinding,
  parseKernelAccountProfile,
} from "@oaath/protocol";
import { hashTypedData, keccak256, stringToHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Oaath, OaathStoreConfiguration } from "../create-oaath.js";
import { createKernelRuntime } from "../kernel/create-kernel-runtime.js";
import { kernelV33Deployment } from "../kernel/deployment/v33.js";
import { type EcdsaWalletClient, ecdsaKey, ecdsaWalletKey } from "../kernel/key/ecdsa.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { sessionOperator } from "../kernel/operator/session.js";
import { kernelGrantCapabilityHash } from "../kernel/permission/approval.js";
import { deriveSessionPolicyProfiles } from "../kernel/permission/profiles.js";
import {
  approveKernelV33Permission,
  kernelV33PermissionEnableTypedData,
  kernelV33PermissionInstallNonce,
} from "../kernel/permission/v33.js";
import type { KernelV33Runtime } from "../kernel/types.js";
import { routingAddress } from "../routing/capabilities.js";
import { GrantStore } from "../store.js";
import { defaultStores, type OwnedDefaultStores } from "./browser-stores.js";
import type { LocalPermissionAuthorization } from "./connection.js";
import { clientCapability, clientFail, clientFailure, mapClientFailure } from "./errors.js";
import { captureChainCapability, type OaathChainCapability } from "./grant-handle.js";
import { loadServiceSession, saveServiceSession, serviceSessionKeyId } from "./service-session.js";

type EnableTypedData = ReturnType<typeof kernelV33PermissionEnableTypedData>;
export interface OaathLocalWallet extends EcdsaWalletClient {
  readonly signTypedData: (
    request: EnableTypedData & Readonly<{ account: `0x${string}` }>,
  ) => Promise<unknown>;
}
export interface OaathLocalApprovalReview {
  readonly account: `0x${string}`;
  readonly chainScope: "all";
  readonly policy: Readonly<GrantPolicy>;
  readonly typedData: EnableTypedData;
}
export interface OaathLocalConfiguration {
  readonly mode: "local";
  readonly owner: OaathLocalWallet;
  /** Existing Kernel v3.3 account with this wallet's ECDSA root. */
  readonly account: `0x${string}`;
  readonly chains: readonly Readonly<OaathChainCapability>[];
  /** Display the decoded policy before the wallet's canonical Kernel prompt. Throw to cancel. */
  readonly onApproval?: (review: Readonly<OaathLocalApprovalReview>) => Promise<void>;
  /** Defaults to the current browser origin. */
  readonly origin?: string;
  /** Defaults to the shared browser IndexedDB stores. */
  readonly stores?: Readonly<OaathStoreConfiguration>;
  readonly now?: () => number;
}

export function createLocalRealm(
  record: Readonly<Record<string, unknown>>,
  compose: (configuration: unknown, authorization: LocalPermissionAuthorization) => Readonly<Oaath>,
): Readonly<Oaath> {
  const fail = clientFailure("oaath_client_input_invalid");
  for (const key of Object.keys(record))
    if (
      !["mode", "owner", "account", "chains", "onApproval", "origin", "stores", "now"].includes(key)
    )
      return fail("local configuration contains an unknown field");
  const address = routingAddress(record.account, "local Kernel account", fail);
  const entries = captureDenseArray(record.chains, "local chains", new WeakSet(), fail);
  if (entries.length < 1 || entries.length > 32)
    return fail("local chains must hold 1 to 32 entries");
  const chains = entries.map(captureChainCapability);
  if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length)
    return fail("local chains repeat a chain");
  const first = chains[0];
  if (!first) return fail("local chain is missing");
  const deployment = kernelV33Deployment(first.chainId);
  const ownerKey = ecdsaWalletKey({
    wallet: record.owner as OaathLocalWallet,
    validator: deployment.ecdsaValidator,
  });
  const wallet = captureRecord(record.owner, "local wallet", new WeakSet(), fail);
  const signTypedData = clientCapability<OaathLocalWallet["signTypedData"]>(
    wallet.signTypedData,
    "wallet signTypedData",
  );
  const onApproval =
    record.onApproval === undefined
      ? null
      : clientCapability<NonNullable<OaathLocalConfiguration["onApproval"]>>(
          record.onApproval,
          "local approval review",
        );
  const now =
    record.now === undefined
      ? () => Math.floor(Date.now() / 1_000)
      : clientCapability<() => number>(record.now, "clock");
  const originValue =
    record.origin ?? (globalThis as { location?: { origin?: string } }).location?.origin;
  const origin =
    typeof originValue === "string"
      ? originValue
      : fail("local mode requires a browser origin or origin override");
  // Capture the same protocol origin/redirect rules before opening custody.
  parseClientBinding({
    version: "oaath.client-binding/v1",
    clientId: "local",
    applicationName: "Local OAAth",
    origin,
    redirectUris: [`${origin}/oaath/local`],
  });
  const account = parseKernelAccountProfile({
    version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    kernelVersion: "0.3.3",
    address,
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: ownerKey.publicMaterial,
    },
  });
  // Origin/account/owner separate both custody and durable Grant contexts. This URL
  // is only a protocol identity; no transport is created or invoked for it.
  const identity = {
    application: {
      applicationId: "local",
      applicationName: "Local OAAth",
      clientId: "local",
      redirectUris: [`${origin}/oaath/local`],
    },
    userHandle: ownerKey.publicMaterial,
    context: {
      version: "oaath.workspace-account-context/v1" as const,
      workspaceId: "local",
      workspaceKind: "personal" as const,
      accountId: address,
    },
    account,
  };
  let inner: Readonly<Oaath> | null = null;
  let composing: Promise<Readonly<Oaath>> | null = null;
  let owned: Readonly<OwnedDefaultStores> | null = null;
  let closed = false;
  let closing: Promise<void> | null = null;
  const active = new Set<Promise<unknown>>();

  async function realm(): Promise<Readonly<Oaath>> {
    if (inner) return inner;
    composing ??= (async () => {
      if (record.stores === undefined) owned = await defaultStores();
      const stores = (record.stores ?? owned?.stores) as OaathStoreConfiguration;
      const custody = { stores, url: origin, origin, bootstrap: identity };
      let session = await loadServiceSession(custody);
      if (session === null) {
        session = { deviceId: crypto.randomUUID(), privateKey: generatePrivateKey() };
        // Local mode promises browser recovery: fail before approval when custody
        // cannot be saved, instead of silently creating an ephemeral Grant.
        await saveServiceSession({ ...custody, session, now });
      }
      const sessionAccount = privateKeyToAccount(session.privateKey);
      const sessionKey = ecdsaKey({
        account: sessionAccount,
        validator: deployment.ecdsaValidator,
      });
      async function approve(request: Readonly<PermissionRequest>): Promise<unknown> {
        const policies = deriveSessionPolicyProfiles(request.policy);
        let scope: Parameters<typeof kernelV33PermissionEnableTypedData>[0] | undefined;
        let approvalRuntime: Readonly<KernelV33Runtime> | undefined;
        // Every configured destination must prove the same account, owner and
        // effective validation nonce before a single all-chain signature exists.
        for (const chain of chains) {
          const options = { deployment: kernelV33Deployment(chain.chainId), reads: chain.reads };
          const ownerRuntime = createKernelRuntime({
            ...options,
            operator: ownerOperator({ key: ownerKey }),
          });
          await ownerRuntime.bindAccount({ address });
          const runtime = createKernelRuntime({
            ...options,
            operator: sessionOperator({ key: sessionKey, policies }),
          });
          const bound = await runtime.bindAccount({ address });
          const nonce = await kernelV33PermissionInstallNonce({
            runtime,
            account: bound,
            reads: chain.reads,
          });
          if (scope && scope.nonce !== nonce)
            return clientFail(
              "oaath_client_state_conflict",
              "configured chains have different Kernel validation nonces",
            );
          if (runtime.validation.kind !== "permission")
            return fail("local runtime is not a permission");
          scope = {
            chainScope: "all",
            account: address,
            nonce,
            permissionId: runtime.validation.permissionId as `0x${string}`,
            packages: runtime.packages,
          };
          approvalRuntime = runtime;
        }
        if (!scope || !approvalRuntime) return fail("no local approval chain exists");
        const typedData = kernelV33PermissionEnableTypedData(scope);
        const digest = hashTypedData(typedData);
        // Copy the display value so a caller cannot mutate the wallet's signed
        // message. The exact policy and typed-data digest remain independently bound.
        await onApproval?.(
          structuredClone({
            account: address,
            chainScope: "all",
            policy: request.policy,
            typedData,
          }),
        );
        const approvalKey = ecdsaKey({
          validator: deployment.ecdsaValidator,
          account: {
            address: ownerKey.publicMaterial,
            async sign({ hash }) {
              if (hash !== digest)
                return clientFail("oaath_client_internal", "local approval digest changed");
              return signTypedData({ ...typedData, account: ownerKey.publicMaterial });
            },
          },
        });
        const bound = await approvalRuntime.bindAccount({ address });
        const installApproval = await approveKernelV33Permission({
          owner: approvalKey,
          runtime: approvalRuntime,
          account: bound,
          nonce: scope.nonce,
        });
        return {
          version: OAATH_PERMISSION_DECISION_VERSION,
          kind: "approve",
          requestId: request.requestId,
          requestHash: hashPermissionRequest(request),
          decidedAt: now(),
          approvedPolicy: request.policy,
          capabilityHash: kernelGrantCapabilityHash(installApproval),
          installApproval,
        };
      }
      inner = compose(
        {
          binding: {
            issuer: origin,
            applicationId: identity.application.applicationId,
            applicationName: identity.application.applicationName,
            clientId: identity.application.clientId,
            origin,
            redirectUri: `${origin}/oaath/local`,
            deviceId: session.deviceId,
            userHandle: identity.userHandle,
            context: identity.context,
            account,
            operatorCredential: {
              version: "oaath.operator-credential-profile/v1",
              kind: "ecdsa",
              address: sessionAccount.address.toLowerCase(),
            },
          },
          stores,
          chains,
          signing: { owner: ownerKey, session: sessionKey },
          localKeyIds: [serviceSessionKeyId(origin, origin, identity)],
          now,
          invalidation: {
            async invalidateCapability(value: { grantId: string; capabilityHash: `0x${string}` }) {
              const saved = await new GrantStore(stores.grants).get(value.grantId);
              if (
                saved?.value.state !== "revoking" ||
                saved.value.approval?.capabilityHash !== value.capabilityHash
              )
                return clientFail(
                  "oaath_client_state_conflict",
                  "local revocation intent is not durable",
                );
              return {
                evidenceHash: keccak256(
                  stringToHex(
                    JSON.stringify(["oaath.local-invalidation/v1", value, saved.storeRevision]),
                  ),
                ),
                invalidatedAt: now(),
              };
            },
          },
        },
        approve,
      );
      return inner;
    })().catch(async (error) => {
      composing = null;
      await owned?.close().catch(() => undefined);
      owned = null;
      return mapClientFailure(error, "local realm could not be opened");
    });
    return composing;
  }
  function activity<T>(work: () => Promise<T>): Promise<T> {
    if (closed) return clientFail("oaath_client_closed", "local realm is closed");
    const task = work().finally(() => active.delete(task));
    active.add(task);
    return task;
  }
  return Object.freeze({
    get binding() {
      if (!inner) return fail("the local binding exists after connect()");
      return inner.binding;
    },
    connect: () => activity(async () => (await realm()).connect()),
    disconnect: (grant: Parameters<Oaath["disconnect"]>[0]) =>
      activity(async () => {
        const result = await (await realm()).disconnect(grant);
        await owned?.close();
        owned = null;
        return result;
      }),
    async close() {
      closed = true;
      closing ??= (async () => {
        await Promise.allSettled([...active]);
        let failure: unknown;
        await inner?.close().catch((error: unknown) => {
          failure = error;
        });
        await owned
          ?.close()
          .then(() => {
            owned = null;
          })
          .catch((error: unknown) => {
            failure ??= error;
          });
        if (failure !== undefined) throw failure;
      })().catch((error) => {
        closing = null;
        throw error;
      });
      await closing;
    },
  });
}
