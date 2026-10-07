/**
 * App access asked for by a member that does not own the account.
 *
 * - In the sign-in popup the member reviews the dapp's request and sends it to
 *   the owner (`AskOwner`); the dapp is sent back at once and receives its
 *   grant only after the owner approves.
 * - The owner approves or rejects from the members view (`PendingRequests`)
 *   or from the link the member shares (`/requests/{id}`, `RequestPage`).
 *   Approving is the same one root signature as a direct grant.
 *
 * @author taek <leekt216@gmail.com>
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type GrantDetail,
  type PendingRequest,
  type PortalAccount,
  PortalApiError,
  type PortalTransaction,
  portalApi,
} from "./api.js";
import { GrantTerms, grantFailure, when } from "./GrantReview.js";
import { reviewedRequest, signGrantApproval } from "./root-signing.js";
import { CancelButton, Frame, message, Notice, QrCode, SignerStep } from "./shared.js";
import { type RememberedSigner, shortAddress, signerDetail } from "./signers.js";

function requestUrl(requestId: string): string {
  return `${location.origin}/requests/${requestId}`;
}

function requestMessage(error: unknown): string {
  const code = error instanceof PortalApiError ? error.code : (error as { code?: string })?.code;
  switch (code) {
    case "relay_forbidden":
      return "Only the account's owner can decide this request.";
    case "relay_already_decided":
      return "This request was already decided.";
    case "relay_expired":
      return "This request has expired. The app has to ask again.";
    case "relay_not_found":
      return "This request doesn't exist.";
    case "network_unavailable":
      return message(error);
    default:
      return grantFailure(error);
  }
}

/** The owner's one signature over the relay's composed request, as it was shown. */
async function approveRequest(
  view: PendingRequest,
  signer: RememberedSigner,
  account: PortalAccount,
): Promise<PendingRequest> {
  const prepared = await portalApi.preparePending(view.request_id);
  const request = reviewedRequest({
    prepared,
    detail: {
      signer: view.permission_request.operatorCredential,
      policy: view.permission_request.policy,
    },
    signer,
    account,
  });
  const artifact = await signGrantApproval({
    request,
    prepared,
    chainId: view.chains[0],
    signer,
    account,
  });
  return portalApi.approvePending(view.request_id, artifact);
}

/** The popup step for a member: the request goes to the owner, the app waits. */
export function AskOwner({
  transaction,
  detail,
  signer,
  account,
  onAsk,
  onCancel,
}: {
  transaction: PortalTransaction;
  detail: GrantDetail;
  signer: RememberedSigner;
  account: PortalAccount;
  onAsk: () => void;
  onCancel: () => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => heading.current?.focus(), []);
  const url = requestUrl(transaction.transaction_id);
  return (
    <section aria-labelledby="ask-heading">
      <h1 id="ask-heading" ref={heading} tabIndex={-1}>
        Ask the owner
      </h1>
      <p className="quiet">
        {signer.label} is a member of <span className="mono">{shortAddress(account.address)}</span>,
        not its owner. {transaction.client_name} gets access once the owner approves.
      </p>
      <GrantTerms
        credential={detail.signer}
        policy={detail.policy}
        chains={detail.chains}
        expiresAt={detail.expires_at}
      />
      <p className="quiet">Share this link with the owner after you send the request.</p>
      <QrCode text={url} label="Request link QR code" />
      <p className="mono link-url" id="request-url">
        {url}
      </p>
      <div className="actions">
        <button type="button" className="primary" onClick={onAsk}>
          Send request to the owner
        </button>
        <button
          type="button"
          className="secondary"
          onClick={() =>
            navigator.clipboard.writeText(url).then(
              () => setCopied(true),
              () => setCopied(false),
            )
          }
        >
          {copied ? "Copied" : "Copy link"}
        </button>
      </div>
      <CancelButton onCancel={onCancel} disabled={false} />
    </section>
  );
}

function RequestSummary({ view }: { view: PendingRequest }) {
  return (
    <>
      <p className="quiet">
        {view.client_name} (<span className="mono">{view.redirect_origin}</span>) asks for access to{" "}
        <span className="mono">{shortAddress(view.address)}</span>, requested by member{" "}
        <span className="mono">{signerDetail(view.member.profile)}</span> on {when(view.created_at)}
        .
      </p>
      <GrantTerms
        credential={view.permission_request.operatorCredential}
        policy={view.permission_request.policy}
        chains={view.chains}
        expiresAt={view.permission_request.expiresAt}
      />
    </>
  );
}

/** `/accounts`: the owner's undecided member requests for one account. */
export function PendingRequests({
  account,
  signer,
  onDecided,
}: {
  account: PortalAccount;
  signer: RememberedSigner;
  /** An approval adds the dapp signer as a member. */
  onDecided: () => void;
}) {
  const [requests, setRequests] = useState<readonly PendingRequest[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    () =>
      portalApi.pendingRequests(account.account_id).then(
        (response) => setRequests(response.requests),
        (failure: unknown) => setError(requestMessage(failure)),
      ),
    [account.account_id],
  );
  useEffect(() => {
    load();
  }, [load]);

  async function run(work: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await work();
      onDecided();
    } catch (failure) {
      setError(requestMessage(failure));
    }
    await load();
    setBusy(false);
  }

  if (requests.length === 0 && !error) return null;
  return (
    <section aria-labelledby="requests-heading" className="members">
      <h2 id="requests-heading">Pending requests</h2>
      <ul className="choices">
        {requests.map((view) => (
          <li key={view.request_id} className="request">
            <RequestSummary view={view} />
            <div className="actions">
              <button
                type="button"
                className="primary"
                disabled={busy}
                aria-label={`Approve ${view.client_name}`}
                onClick={() => run(() => approveRequest(view, signer, account))}
              >
                Approve and sign
              </button>
              <button
                type="button"
                className="secondary"
                disabled={busy}
                aria-label={`Reject ${view.client_name}`}
                onClick={() => run(() => portalApi.rejectPending(view.request_id))}
              >
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

const STATUS_TEXT: Readonly<Record<PendingRequest["status"], string>> = {
  pending: "Waiting for the owner's approval.",
  approved: "The owner approved this request.",
  rejected: "The owner declined this request.",
  expired: "This request expired.",
};

/** `/requests/{id}`: the link a member shares with the account's owner. */
export function RequestPage({ requestId }: { requestId: string }) {
  const [signer, setSigner] = useState<RememberedSigner | null>(null);
  const [view, setView] = useState<PendingRequest | null>(null);
  const [account, setAccount] = useState<PortalAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!signer) return;
    setFailure(null);
    Promise.all([portalApi.pendingRequest(requestId), portalApi.signerAccounts(signer.signer_id)])
      .then(([loaded, accounts]) => {
        setView(loaded);
        setAccount(
          accounts.accounts.find(
            (entry) => entry.account_id === loaded.account_id && entry.role === "root",
          ) ?? null,
        );
      })
      .catch((cause: unknown) => setFailure(requestMessage(cause)));
  }, [requestId, signer]);

  const changeSigner = () => {
    portalApi.signOut().catch(() => {});
    setView(null);
    setFailure(null);
    setSigner(null);
  };

  async function run(work: () => Promise<PendingRequest>) {
    setBusy(true);
    setError(null);
    try {
      setView(await work());
    } catch (cause) {
      setError(requestMessage(cause));
    }
    setBusy(false);
  }

  return (
    <Frame>
      <header className="client">
        <p className="eyebrow">App access request</p>
      </header>
      {!signer && (
        <>
          <p className="quiet">Sign in as the account's owner to review this request.</p>
          <SignerStep onChosen={setSigner} />
        </>
      )}
      {signer && failure && (
        <section role="status">
          <p className="error" role="alert">
            {failure}
          </p>
          <button type="button" className="link" onClick={changeSigner}>
            Use another signer
          </button>
        </section>
      )}
      {signer && !failure && !view && (
        <p className="quiet" aria-live="polite">
          Loading request…
        </p>
      )}
      {signer && view && !account && (
        <Notice title="Waiting for the owner">
          {view.status === "pending"
            ? "Share this page's link with the account's owner."
            : STATUS_TEXT[view.status]}
        </Notice>
      )}
      {signer && view && account && (
        <section aria-labelledby="request-heading">
          <h1 id="request-heading">Review app access</h1>
          <RequestSummary view={view} />
          <p className="quiet" aria-live="polite" id="request-status">
            {STATUS_TEXT[view.status]}
          </p>
          {view.status === "pending" && (
            <div className="actions">
              <button
                type="button"
                className="primary"
                disabled={busy}
                onClick={() => run(() => approveRequest(view, signer, account))}
              >
                Approve and sign
              </button>
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => run(() => portalApi.rejectPending(view.request_id))}
              >
                Reject
              </button>
            </div>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </section>
      )}
    </Frame>
  );
}
