/**
 * Owner-operation review: the exact transaction a dapp asks the account's root
 * to sign. Everything shown comes from the request the portal re-captured and
 * bound to the chosen account; the one signature is over its UserOperation hash.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OwnerOperationRequest } from "@oaath/protocol";
import { useEffect, useMemo, useRef, useState } from "react";
import type { PortalAccount } from "./api.js";
import { CHAINS, ether, SELECTORS } from "./GrantReview.js";
import { reviewedOperation, signOperation } from "./operation-signing.js";
import { RootSigningError } from "./root-signing.js";
import { type RememberedSigner, shortAddress } from "./signers.js";

function gwei(wei: string): string {
  const value = BigInt(wei);
  const whole = value / 10n ** 9n;
  const fraction = (value % 10n ** 9n).toString().padStart(9, "0").replace(/0+$/u, "");
  return `${whole}${fraction ? `.${fraction}` : ""} gwei`;
}

function failure(error: unknown): string {
  switch (error instanceof RootSigningError ? error.code : (error as { code?: string })?.code) {
    case "request-mismatch":
    case "request-invalid":
      return "This transaction is not for this account and its owner, so OAAth will not sign it.";
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

function Call({ call }: { call: OwnerOperationRequest["calls"][number] }) {
  const selector = call.data.length >= 10 ? call.data.slice(0, 10) : null;
  const name = selector ? SELECTORS[selector] : undefined;
  return (
    <li>
      <span className="call-name">
        {selector === null ? "Send" : (name ?? <span className="mono">{selector}</span>)}
      </span>{" "}
      to <span className="mono">{call.target}</span>
      <span className="choice-detail">
        Sends {ether(call.value)}
        {selector !== null && ` · ${(call.data.length - 2) / 2} bytes of call data`}
      </span>
    </li>
  );
}

export function OperationReview({
  clientName,
  request: relayed,
  signer,
  account,
  onApproved,
  onCancel,
}: {
  clientName: string;
  request: unknown;
  signer: RememberedSigner;
  account: PortalAccount;
  onApproved: (artifact: string) => void;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const reviewed = useMemo(() => {
    try {
      return { request: reviewedOperation({ request: relayed, signer, account }), error: null };
    } catch (cause) {
      return { request: null, error: failure(cause) };
    }
  }, [relayed, signer, account]);

  useEffect(() => heading.current?.focus(), []);

  async function approve() {
    if (!reviewed.request) return;
    setBusy(true);
    setError(null);
    try {
      onApproved(await signOperation(reviewed.request, signer));
    } catch (cause) {
      setError(failure(cause));
      setBusy(false);
    }
  }

  const request = reviewed.request;
  const operation = request?.userOperation;
  const phone = signer.profile.kind === "p256";
  return (
    <section aria-labelledby="operation-heading">
      <h1 id="operation-heading" ref={heading} tabIndex={-1}>
        Review transaction
      </h1>
      <p className="quiet">
        {clientName} asks your account <span className="mono">{shortAddress(account.address)}</span>{" "}
        to make this exact transaction.
      </p>
      {request && operation && (
        <dl className="review">
          <dt>Calls</dt>
          <dd>
            <ul className="calls">
              {request.calls.map((call, index) => (
                // Calls are an ordered, immutable list: the position is the identity.
                // biome-ignore lint/suspicious/noArrayIndexKey: the reviewed list never reorders
                <Call key={index} call={call} />
              ))}
            </ul>
          </dd>
          <dt>Chain</dt>
          <dd>{CHAINS[request.chainId] ?? `Chain ${request.chainId}`}</dd>
          <dt>Fees</dt>
          <dd>
            Up to {gwei(operation.maxFeePerGas)} per gas (priority{" "}
            {gwei(operation.maxPriorityFeePerGas)})
          </dd>
          <dt>Paid by</dt>
          <dd>
            {operation.paymaster === null ? (
              "Your account"
            ) : (
              <>
                Paymaster <span className="mono">{operation.paymaster.address}</span>
              </>
            )}
          </dd>
          {operation.factory !== null && (
            <>
              <dt>Account</dt>
              <dd>Deployed by this transaction</dd>
            </>
          )}
          <dt>Transaction hash</dt>
          <dd className="mono" title={request.userOperationHash}>
            {shortAddress(request.userOperationHash)}
          </dd>
        </dl>
      )}
      {request && (
        <p className="notice">
          Approving asks {signer.label} for one signature over this one transaction. {clientName}{" "}
          submits it; it cannot be changed after you sign, and it grants nothing else.
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="primary"
          disabled={!request || busy || phone}
          onClick={approve}
        >
          Approve and sign
        </button>
      </div>
      {(error ?? reviewed.error) && (
        <p className="error" role="alert">
          {error ?? reviewed.error}
        </p>
      )}
      <button type="button" className="cancel" disabled={busy} onClick={onCancel}>
        Cancel and return to the app
      </button>
    </section>
  );
}
