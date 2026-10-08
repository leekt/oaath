/**
 * Grant review: what the dapp's signer may do with this account, and the one
 * root signature that approves it. Everything shown comes from the request the
 * relay composed, after the portal checked it is the dapp's own request.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { GrantPolicy, OperatorCredentialProfile, PermissionRequest } from "@oaath/protocol";
import { useEffect, useRef, useState } from "react";
import {
  type GrantDetail,
  type PortalAccount,
  PortalApiError,
  type PortalTransaction,
  type PrepareGrantResponse,
  portalApi,
} from "./api.js";
import { RootSigningError, reviewedRequest, signGrantApproval } from "./root-signing.js";
import { type RememberedSigner, shortAddress } from "./signers.js";

/** Well-known ERC-20 selectors; anything else is shown as its hex selector. */
export const SELECTORS: Readonly<Record<string, string>> = {
  "0xa9059cbb": "transfer",
  "0x095ea7b3": "approve",
  "0x23b872dd": "transferFrom",
  "0x39509351": "increaseAllowance",
  "0xa457c2d7": "decreaseAllowance",
};

export const CHAINS: Readonly<Record<number, string>> = {
  1: "Ethereum",
  10: "OP Mainnet",
  8453: "Base",
  42161: "Arbitrum One",
  11155111: "Sepolia",
  84532: "Base Sepolia",
  421614: "Arbitrum Sepolia",
};

export function ether(wei: string): string {
  const value = BigInt(wei);
  const whole = value / 10n ** 18n;
  const fraction = (value % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/u, "");
  return `${whole}${fraction ? `.${fraction}` : ""} ETH`;
}

export function when(seconds: number): string {
  return new Date(seconds * 1_000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function duration(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400} day${seconds === 86_400 ? "" : "s"}`;
  if (seconds % 3_600 === 0) return `${seconds / 3_600} hour${seconds === 3_600 ? "" : "s"}`;
  return `${seconds} seconds`;
}

function limit(policy: GrantPolicy): string {
  const { count, intervalSeconds } = policy.perChainOperationLimit;
  const times = `${count} operation${count === 1 ? "" : "s"}`;
  return intervalSeconds === null
    ? `Up to ${times} per chain in total`
    : `Up to ${times} per chain every ${duration(intervalSeconds)}`;
}

function signerText(credential: OperatorCredentialProfile): string {
  return credential.kind === "ecdsa"
    ? `Ethereum key ${credential.address}`
    : `Passkey ${shortAddress(credential.publicKey)}`;
}

export function grantFailure(error: unknown): string {
  // The page shows a short message; the console keeps the cause for diagnosis.
  console.error("[oaath-portal] grant", error);
  if (error instanceof PortalApiError && error.status === 403)
    return "Only this account's owner can approve a grant.";
  switch (error instanceof RootSigningError ? error.code : (error as { code?: string })?.code) {
    case "request-mismatch":
    case "request-invalid":
    case "digest-mismatch":
      return "This request does not match what the app asked for, so OAAth will not sign it.";
    case "account-unreadable":
      return "The account could not be read on Arbitrum Sepolia, so nothing was signed. Try again.";
    case "wallet-unavailable":
      return "Your wallet is not available in this browser. Open it and try again.";
    case "wallet-account-mismatch":
      return "Switch your wallet to the account you signed in with, then try again.";
    case "passkey-cancelled":
    case "kernel_runtime_signing_failed":
    case "kernel_runtime_signature_invalid":
      return "The signature was not completed.";
    default:
      return "Something went wrong. Please try again.";
  }
}

/** What a dapp's signer may do: shown to a root before it signs, and to a member before it asks. */
export function GrantTerms({
  credential,
  policy,
  chains,
  expiresAt,
}: {
  credential: OperatorCredentialProfile;
  policy: GrantPolicy;
  chains: readonly number[];
  /** Unix seconds. */
  expiresAt: number;
}) {
  return (
    <dl className="review">
      <dt>App signer</dt>
      <dd className="mono">{signerText(credential)}</dd>
      <dt>Allowed calls</dt>
      <dd>
        <ul className="calls">
          {policy.calls.map((call) => (
            <li key={`${call.target}:${call.selector}`}>
              <span className="call-name">
                {SELECTORS[call.selector] ?? <span className="mono">{call.selector}</span>}
              </span>{" "}
              on <span className="mono">{call.target}</span>
              <span className="choice-detail">Sends up to {ether(call.valueLimit)}</span>
            </li>
          ))}
        </ul>
      </dd>
      <dt>Valid</dt>
      <dd>
        From {when(policy.validAfter)}
        {policy.validUntil !== null && ` until ${when(policy.validUntil)}`}
      </dd>
      <dt>Limit</dt>
      <dd>{limit(policy)}</dd>
      <dt>Chains</dt>
      <dd>{chains.map((chain) => CHAINS[chain] ?? `Chain ${chain}`).join(", ")}</dd>
      <dt>Request expires</dt>
      <dd>{when(expiresAt)}</dd>
    </dl>
  );
}

export function GrantReview({
  transaction,
  detail,
  signer,
  account,
  onApproved,
  onCancel,
}: {
  transaction: PortalTransaction;
  detail: GrantDetail;
  signer: RememberedSigner;
  account: PortalAccount;
  onApproved: (artifact: string) => void;
  onCancel: () => void;
}) {
  const [prepared, setPrepared] = useState<{
    response: PrepareGrantResponse;
    request: Readonly<PermissionRequest>;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), []);
  useEffect(() => {
    portalApi
      .prepareGrant(transaction.transaction_id, {
        signer_id: signer.signer_id,
        account_id: account.account_id,
      })
      .then((response) =>
        setPrepared({
          response,
          request: reviewedRequest({ prepared: response, detail, signer, account }),
        }),
      )
      .catch((cause: unknown) => setError(grantFailure(cause)));
  }, [transaction.transaction_id, detail, signer, account]);

  async function approve() {
    if (!prepared) return;
    setBusy(true);
    setError(null);
    try {
      onApproved(
        await signGrantApproval({
          request: prepared.request,
          prepared: prepared.response,
          chainId: detail.chains[0],
          signer,
          account,
        }),
      );
    } catch (cause) {
      setError(grantFailure(cause));
      setBusy(false);
    }
  }

  const request = prepared?.request;
  return (
    <section aria-labelledby="review-heading">
      <h1 id="review-heading" ref={heading} tabIndex={-1}>
        Review access
      </h1>
      <p className="quiet">
        {transaction.client_name} asks to use its own signer with your account{" "}
        <span className="mono">{shortAddress(account.address)}</span>, within the limits below.
      </p>
      {!request && !error && (
        <p className="quiet" aria-live="polite">
          Preparing the request…
        </p>
      )}
      {request && (
        <GrantTerms
          credential={request.operatorCredential}
          policy={request.policy}
          chains={detail.chains}
          expiresAt={request.expiresAt}
        />
      )}
      {request && (
        <p className="notice">
          Approving asks {signer.label} for one signature. It lets {transaction.client_name}'s
          signer act within this policy on your account. Signing in by itself approves nothing.
        </p>
      )}
      <div className="actions">
        <button type="button" className="primary" disabled={!request || busy} onClick={approve}>
          Approve and sign
        </button>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="button" className="cancel" disabled={busy} onClick={onCancel}>
        Cancel and return to the app
      </button>
    </section>
  );
}
