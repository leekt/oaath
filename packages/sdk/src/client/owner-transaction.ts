/**
 * One exact plain transaction sent by an OAAth signer's own wallet, from the
 * issuer's portal: a factory call with value, a contract creation, or an
 * EntryPoint `handleOps` after a bundler refused the signed operation.
 *
 * ```text
 * requestOwnerTransaction()  identity = hashOwnerTransactionRequest(request),
 *                            known before anything is sent
 *                            PAR [{ type: "oaath_transaction", request }]
 *                            popup -> the signer reviews; its wallet sends
 *                            token -> [{ type, request, transaction_hash }]
 * portalWallet()             the same, behind the connected-EOA wallet shape
 *                            (`eth_chainId`, `eth_accounts`,
 *                            `eth_sendTransaction`) for `payer`
 * ```
 *
 * OAAth never sends and cannot prove the hash is the request's transaction:
 * observe it on chain. A closed popup or lost answer means "unknown", never
 * "not sent": check the sender's nonce before asking again.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  hashOwnerTransactionRequest,
  type OwnerTransactionRequest,
  parseOwnerTransactionRequest,
} from "@oaath/protocol";
import { toHex } from "cetane/utils";
import { clientFail, exactClientRecord, mapClientFailure } from "./errors.js";
import {
  authorizeThroughPopup,
  authorizeWithLauncher,
  type OaathAuthorizationLauncher,
  type OaathLogin,
  type OaathLoginOptions,
  openAuthorizationPopup,
} from "./oauth-login.js";

export interface OaathOwnerTransactionOptions extends OaathLoginOptions {
  /** The exact transaction; `to: null` creates a contract. */
  readonly request: Readonly<OwnerTransactionRequest>;
  /** A popup the caller opened synchronously in the user's gesture. */
  readonly popup?: Window;
  readonly launch?: OaathAuthorizationLauncher;
}

export interface OaathSentOwnerTransaction {
  readonly request: Readonly<OwnerTransactionRequest>;
  /** `hashOwnerTransactionRequest(request)`: the identity held before sending. */
  readonly requestHash: `0x${string}`;
  /** The hash the signer's wallet returned; observe it on chain. */
  readonly transactionHash: `0x${string}`;
  readonly login: Readonly<OaathLogin>;
}

/**
 * Asks the signer whose wallet is `request.from` to review and send one exact
 * transaction in the issuer's portal. Fails with `oaath_client_popup_blocked`,
 * `oaath_client_access_denied` (cancelled or rejected), or
 * `oaath_client_state_conflict` (source `oauth_transaction_mismatch`) when the
 * released transaction is not this request.
 */
export async function requestOwnerTransaction(
  value: OaathOwnerTransactionOptions,
): Promise<Readonly<OaathSentOwnerTransaction>> {
  if (!value || typeof value !== "object")
    return clientFail("oaath_client_input_invalid", "transaction options are required");
  const { request: requestValue, popup: given, launch, ...options } = value;
  if (launch !== undefined && typeof launch !== "function")
    return clientFail("oaath_client_capability_invalid", "launch must be a function");
  if (launch !== undefined && given !== undefined)
    return clientFail("oaath_client_input_invalid", "pass a popup or a launcher, not both");
  // Open inside the user's gesture, before anything is awaited.
  const popup = launch ? null : (given ?? openAuthorizationPopup());
  try {
    let request: Readonly<OwnerTransactionRequest>;
    try {
      request = parseOwnerTransactionRequest(requestValue);
    } catch (error) {
      return mapClientFailure(error, "the owner transaction request is invalid");
    }
    const requestHash = hashOwnerTransactionRequest(request);
    const extra = {
      authorization_details: JSON.stringify([{ type: "oaath_transaction", request }]),
    };
    const { released } = popup
      ? await authorizeThroughPopup(popup, options, extra)
      : await authorizeWithLauncher(launch as OaathAuthorizationLauncher, options, extra);
    if (released === null)
      return clientFail("oaath_client_issuer_rejected", "the issuer left the transaction pending");
    const mismatch = (): never =>
      clientFail(
        "oaath_client_state_conflict",
        "the sent transaction is not the one this application requested",
        "oauth_transaction_mismatch",
      );
    const details = released.token.authorization_details;
    if (!Array.isArray(details) || details.length !== 1) return mismatch();
    const detail = exactClientRecord(
      details[0],
      ["type", "request", "transaction_hash"],
      "OAuth transaction detail",
      new WeakSet(),
      "oaath_client_issuer_unavailable",
    );
    if (
      detail.type !== "oaath_transaction" ||
      JSON.stringify(detail.request) !== JSON.stringify(request) ||
      typeof detail.transaction_hash !== "string" ||
      !/^0x[0-9a-f]{64}$/u.test(detail.transaction_hash)
    )
      return mismatch();
    return Object.freeze({
      request,
      requestHash,
      transactionHash: detail.transaction_hash as `0x${string}`,
      login: released.login,
    });
  } finally {
    popup?.close();
  }
}

export interface OaathPortalWalletOptions extends OaathLoginOptions {
  readonly chainId: number;
  /** The signer's own wallet address that sends. */
  readonly from: `0x${string}`;
  /**
   * Opens the portal somewhere other than a fresh popup. A send that runs
   * after other awaits (for example the connected-EOA fallback) is outside
   * the user's gesture, where browsers block a new popup.
   */
  readonly launch?: OaathAuthorizationLauncher;
}

/**
 * The connected-EOA wallet shape (`payer: { kind: "connected-eoa", wallet }`)
 * whose every `eth_sendTransaction` is reviewed and sent by the signer's own
 * wallet in the portal: flag "allow owner wallet to send tx directly", and
 * the EntryPoint-direct fallback.
 */
export function portalWallet(value: OaathPortalWalletOptions) {
  if (!value || typeof value !== "object")
    return clientFail("oaath_client_input_invalid", "portal wallet options are required");
  const { chainId, from, launch, ...login } = value;
  if (!Number.isSafeInteger(chainId) || chainId < 1)
    return clientFail("oaath_client_input_invalid", "portal wallet chain is invalid");
  if (typeof from !== "string" || !/^0x[0-9a-f]{40}$/u.test(from))
    return clientFail("oaath_client_input_invalid", "portal wallet sender must be lowercase");
  return Object.freeze({
    account: Object.freeze({ address: from }),
    async request(input: {
      method: string;
      params?: readonly Readonly<{
        from?: string;
        to?: `0x${string}` | null;
        data?: `0x${string}`;
        value?: `0x${string}`;
        chainId?: `0x${string}`;
      }>[];
    }): Promise<unknown> {
      if (input.method === "eth_chainId") return toHex(chainId);
      if (input.method === "eth_accounts") return [from];
      if (input.method !== "eth_sendTransaction")
        return clientFail("oaath_client_capability_invalid", "portal wallet method is unsupported");
      const [call] = input.params ?? [];
      if (
        !call ||
        (call.from !== undefined && call.from.toLowerCase() !== from) ||
        (call.chainId !== undefined && BigInt(call.chainId) !== BigInt(chainId))
      )
        return clientFail("oaath_client_input_invalid", "the transaction is not for this wallet");
      const sent = await requestOwnerTransaction({
        ...login,
        ...(launch === undefined ? {} : { launch }),
        request: {
          version: "oaath.owner-transaction-request/v1",
          chainId,
          from,
          to: call.to ?? null,
          value: BigInt(call.value ?? "0x0").toString(10),
          data: call.data ?? "0x",
        },
      });
      return sent.transactionHash;
    },
  });
}
