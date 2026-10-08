/**
 * The "Login with OAAth" popup: sign in with a signer, then choose an account,
 * then return to the dapp. Signing in proves the signer (a passkey assertion
 * or a wallet's Sign-In with Ethereum message) and approves nothing. A grant
 * adds one review in which the account root signs the dapp's request; a
 * member that is not the root sends the request to the root instead
 * (`Requests.tsx`). A signer without an account may ask an existing account's owner to add it
 * (`/link/{id}`, `Links.tsx`).
 *
 * @author taek <leekt216@gmail.com>
 */
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import {
  type DecisionRequest,
  type GrantDetail,
  type OperationDetail,
  type PortalAccount,
  PortalApiError,
  type PortalTransaction,
  portalApi,
  transactionIdFromRequestUri,
} from "./api.js";
import { GrantReview } from "./GrantReview.js";
import { LinkApproval, LinkRequest, ManageAccounts } from "./Links.js";
import { OperationReview } from "./OperationReview.js";
import { AskOwner, RequestPage } from "./Requests.js";
import { CancelButton, Frame, message, Notice, SignerStep } from "./shared.js";
import { type RememberedSigner, rememberSigner, shortAddress } from "./signers.js";

/** Module discovery loads only when an account is imported. */
const ImportAccount = lazy(() =>
  import("./ImportAccount.js").then((module) => ({ default: module.ImportAccount })),
);

type Step =
  | { readonly name: "signer" }
  | { readonly name: "account"; readonly signer: RememberedSigner }
  /** A grant transaction: the account root reviews and signs the dapp's request. */
  | { readonly name: "review"; readonly signer: RememberedSigner; readonly account: PortalAccount }
  /** A grant chosen by a member that is not the root: the root decides later. */
  | { readonly name: "ask"; readonly signer: RememberedSigner; readonly account: PortalAccount }
  | { readonly name: "returning" };

export function App() {
  const params = new URLSearchParams(location.search);
  const link = /^\/link\/([A-Za-z0-9._~-]{1,256})$/u.exec(location.pathname)?.[1];
  if (link) return <LinkApproval linkId={link} />;
  const request = /^\/requests\/([A-Za-z0-9._~-]{1,256})$/u.exec(location.pathname)?.[1];
  if (request) return <RequestPage requestId={request} />;
  if (location.pathname === "/accounts") return <ManageAccounts />;
  if (location.pathname !== "/authorize") return <Landing />;
  const transactionId = transactionIdFromRequestUri(params.get("request_uri"));
  if (!transactionId || !params.get("client_id"))
    return (
      <Frame>
        <Notice title="This sign-in link is incomplete">
          Return to the app you came from and start again.
        </Notice>
      </Frame>
    );
  return <Authorize transactionId={transactionId} />;
}

function Landing() {
  return (
    <Frame>
      <h1>OAAth</h1>
      <p className="lede">
        One account for every app. Start from an app's “Login with OAAth” button.
      </p>
      <p>
        <a href="/accounts">Manage your accounts</a>
      </p>
      <p>
        <a href="https://oaath-demo.taek.tech">Try the demo app</a>
      </p>
    </Frame>
  );
}

function Authorize({ transactionId }: { transactionId: string }) {
  const [transaction, setTransaction] = useState<PortalTransaction | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [step, setStep] = useState<Step>({ name: "signer" });

  useEffect(() => {
    portalApi
      .transaction(transactionId)
      .then(setTransaction, (error: unknown) =>
        setFailure(
          error instanceof PortalApiError && error.status === 404
            ? "This sign-in request has expired or was already used."
            : message(error),
        ),
      );
  }, [transactionId]);

  async function decide(decision: DecisionRequest) {
    setStep({ name: "returning" });
    try {
      const { redirect } = await portalApi
        .decide(transactionId, decision)
        // A lost reply or an already-recorded decision recovers the sealed redirect.
        .catch(() => portalApi.redirect(transactionId));
      location.assign(redirect);
    } catch (error) {
      setFailure(message(error));
    }
  }

  function finish(signer: RememberedSigner, account: PortalAccount, artifact?: string) {
    rememberSigner({ ...signer, lastUsedAt: Date.now() });
    return decide({
      outcome: "approved",
      signer_id: signer.signer_id,
      account_id: account.account_id,
      ...(artifact === undefined ? {} : { artifact }),
    });
  }

  // The dapp's redirect then carries error=access_denied.
  const cancel = () => decide({ outcome: "cancelled" });

  if (failure)
    return (
      <Frame>
        <Notice title="We couldn't continue">{failure}</Notice>
      </Frame>
    );
  if (!transaction)
    return (
      <Frame>
        <p className="quiet" aria-live="polite">
          Loading sign-in…
        </p>
      </Frame>
    );
  const grant = transaction.authorization_details.find(
    (detail): detail is GrantDetail => detail.type === "oaath_grant",
  );
  const operation = transaction.authorization_details.find(
    (detail): detail is OperationDetail => detail.type === "oaath_operation",
  );
  if (transaction.expires_at * 1000 <= Date.now())
    return (
      <Frame>
        <Notice title="This sign-in request has expired">
          Return to {transaction.client_name} and start again.
        </Notice>
      </Frame>
    );
  return (
    <Frame>
      <header className="client">
        <p className="eyebrow">Login with OAAth</p>
        <p className="client-name">{transaction.client_name}</p>
        <p className="quiet">
          returns to <span className="mono">{transaction.redirect_origin}</span>
        </p>
      </header>
      {step.name === "signer" && (
        <SignerStep onChosen={(signer) => setStep({ name: "account", signer })} onCancel={cancel} />
      )}
      {step.name === "account" && (
        <AccountStep
          signer={step.signer}
          onBack={() => {
            // Best effort: the session also expires on its own.
            portalApi.signOut().catch(() => {});
            setStep({ name: "signer" });
          }}
          rootOnly={operation !== undefined}
          only={operation?.request.userOperation.sender}
          onChosen={(account) =>
            grant && account.role !== "root"
              ? setStep({ name: "ask", signer: step.signer, account })
              : grant || operation
                ? setStep({ name: "review", signer: step.signer, account })
                : finish(step.signer, account)
          }
          onCancel={cancel}
        />
      )}
      {step.name === "review" && grant && (
        <GrantReview
          transaction={transaction}
          detail={grant}
          signer={step.signer}
          account={step.account}
          onApproved={(artifact) => finish(step.signer, step.account, artifact)}
          onCancel={cancel}
        />
      )}
      {step.name === "ask" && grant && (
        <AskOwner
          transaction={transaction}
          detail={grant}
          signer={step.signer}
          account={step.account}
          onAsk={() => {
            rememberSigner({ ...step.signer, lastUsedAt: Date.now() });
            decide({
              outcome: "request_approval",
              signer_id: step.signer.signer_id,
              account_id: step.account.account_id,
            });
          }}
          onCancel={cancel}
        />
      )}
      {step.name === "review" && operation && (
        <OperationReview
          clientName={transaction.client_name}
          request={operation.request}
          signer={step.signer}
          account={step.account}
          onApproved={(artifact) => finish(step.signer, step.account, artifact)}
          onCancel={cancel}
        />
      )}
      {step.name === "returning" && (
        <p className="quiet" aria-live="polite">
          Returning to {transaction.client_name}…
        </p>
      )}
    </Frame>
  );
}

const ROLE_LABEL: Readonly<Record<PortalAccount["role"], string>> = {
  root: "Owner",
  permission: "Signer",
};

function AccountStep({
  signer,
  rootOnly,
  only,
  onBack,
  onChosen,
  onCancel,
}: {
  signer: RememberedSigner;
  /** An owner operation is signed by an account's root: other memberships are not offered. */
  rootOnly: boolean;
  /** An owner operation names its one account: no other is offered. */
  only?: string | undefined;
  onBack: () => void;
  onChosen: (account: PortalAccount) => void;
  onCancel: () => void;
}) {
  const [accounts, setAccounts] = useState<readonly PortalAccount[] | null>(null);
  const [linking, setLinking] = useState(false);
  const [importing, setImporting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), []);
  /** Reloaded when a link is approved, so the newly joined account appears. */
  const load = useCallback(
    () =>
      portalApi.signerAccounts(signer.signer_id).then(
        (response) =>
          setAccounts(
            response.accounts.filter(
              (account) =>
                (!rootOnly || account.role === "root") &&
                (only === undefined || account.address === only),
            ),
          ),
        (failure: unknown) => setError(message(failure)),
      ),
    [signer.signer_id, rootOnly, only],
  );
  useEffect(() => {
    load();
  }, [load]);
  const linked = useCallback(() => {
    setLinking(false);
    load();
  }, [load]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const body = {
        root_signer_id: signer.signer_id,
        creation_key: Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join(""),
      };
      // A lost reply is retried once with the same key: it answers the same
      // account, never a second one.
      const created = await portalApi
        .createAccount(body)
        .catch((failure: unknown) =>
          failure instanceof PortalApiError && failure.code === "network_unavailable"
            ? portalApi.createAccount(body)
            : Promise.reject(failure),
        );
      setAccounts((current) => [
        ...(current ?? []).filter((account) => account.account_id !== created.account_id),
        { ...created, role: "root", status: "active" },
      ]);
    } catch (failure) {
      setError(message(failure));
    }
    setBusy(false);
  }

  return (
    <section aria-labelledby="account-heading">
      <h1 id="account-heading" ref={heading} tabIndex={-1}>
        Choose an account
      </h1>
      <p className="quiet">
        Signing in as {signer.label}{" "}
        <button type="button" className="link" onClick={onBack}>
          Change
        </button>
      </p>
      {accounts === null && !error && (
        <p className="quiet" aria-live="polite">
          Loading accounts…
        </p>
      )}
      {accounts?.length === 0 && (
        <p className="quiet">
          {rootOnly
            ? "This signer owns no account yet. Only an account's owner can sign this."
            : "This signer has no account yet."}
        </p>
      )}
      {accounts && accounts.length > 0 && (
        <ul className="choices">
          {accounts.map((account) => (
            <li key={account.account_id}>
              <button
                type="button"
                className="choice"
                // The owner suspended this signer: it cannot sign in as the account.
                disabled={busy || account.status === "suspended"}
                aria-label={`Smart account ${account.address}, ${ROLE_LABEL[account.role]}${
                  account.status === "suspended" ? ", suspended" : ""
                }`}
                onClick={() => onChosen(account)}
              >
                <span className="badge badge-account" aria-hidden="true" />
                <span className="choice-text">
                  <span className="choice-title mono">{shortAddress(account.address)}</span>
                  <span className="choice-detail">
                    Smart account · {ROLE_LABEL[account.role]}
                    {"address" in account.profile && " · Imported"}
                    {account.status === "suspended" && " · Suspended by the owner"}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={create}>
          Create account
        </button>
        {!rootOnly && (
          <button
            type="button"
            className="secondary"
            aria-expanded={linking}
            aria-controls="link-request"
            disabled={busy}
            onClick={() => setLinking(!linking)}
          >
            Link to an existing account
          </button>
        )}
        <button
          type="button"
          className="secondary"
          aria-expanded={importing}
          aria-controls="import-account"
          disabled={busy}
          onClick={() => setImporting(!importing)}
        >
          Import an existing account
        </button>
      </div>
      {linking && <LinkRequest signer={signer} onApproved={linked} />}
      {importing && (
        <Suspense fallback={<p className="quiet">Loading…</p>}>
          <ImportAccount
            signer={signer}
            onImported={() => {
              setImporting(false);
              load();
            }}
          />
        </Suspense>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <CancelButton onCancel={onCancel} disabled={busy} />
    </section>
  );
}
