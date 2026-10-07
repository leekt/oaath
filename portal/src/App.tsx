/**
 * The "Login with OAAth" popup: choose a signer, then an account, then return
 * to the dapp. Choosing is the whole login; nothing here signs anything. A
 * grant adds one review in which the account root signs the dapp's request.
 *
 * @author taek <leekt216@gmail.com>
 */
import { useEffect, useRef, useState } from "react";
import {
  type DecisionRequest,
  type PortalAccount,
  PortalApiError,
  type PortalTransaction,
  portalApi,
  transactionIdFromRequestUri,
} from "./api.js";
import { GrantReview } from "./GrantReview.js";
import {
  type AnnouncedWallet,
  connectWallet,
  createPasskey,
  identifyPasskey,
  type NewSigner,
  type RememberedSigner,
  rememberedSigners,
  rememberSigner,
  shortAddress,
  signerDetail,
  watchWallets,
} from "./signers.js";

type Step =
  | { readonly name: "signer" }
  | { readonly name: "account"; readonly signer: RememberedSigner }
  /** A grant transaction: the account root reviews and signs the dapp's request. */
  | { readonly name: "review"; readonly signer: RememberedSigner; readonly account: PortalAccount }
  | { readonly name: "returning" };

function message(error: unknown): string {
  const code = error instanceof PortalApiError ? error.code : (error as { code?: string })?.code;
  switch (code) {
    case "network_unavailable":
      return "OAAth is unreachable. Check your connection and try again.";
    case "cancelled":
    case "timeout":
      return "The passkey prompt was dismissed.";
    case "already-registered":
      return "This passkey is already on this device.";
    case "passkey-unknown":
      return "This passkey isn't registered with OAAth. Add it as a new signer instead.";
    case "unsupported":
    case "rp-mismatch":
      return "This browser cannot create a passkey here.";
    default:
      return "Something went wrong. Please try again.";
  }
}

export function App() {
  const params = new URLSearchParams(location.search);
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
  const grant = transaction.authorization_details.find((detail) => detail.type === "oaath_grant");
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
          onBack={() => setStep({ name: "signer" })}
          rootOnly={grant !== undefined}
          onChosen={(account) =>
            grant
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
      {step.name === "returning" && (
        <p className="quiet" aria-live="polite">
          Returning to {transaction.client_name}…
        </p>
      )}
    </Frame>
  );
}

function SignerStep({
  onChosen,
  onCancel,
}: {
  onChosen: (signer: RememberedSigner) => void;
  onCancel: () => void;
}) {
  const [signers] = useState(rememberedSigners);
  const [adding, setAdding] = useState(false);
  const [wallets, setWallets] = useState<AnnouncedWallet[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), []);
  useEffect(() => (adding ? watchWallets(setWallets) : undefined), [adding]);

  async function add(create: () => Promise<NewSigner | null>) {
    setBusy(true);
    setError(null);
    try {
      const created = await create();
      if (!created) throw Object.assign(new Error("unknown passkey"), { code: "passkey-unknown" });
      const { signerId, ...fields } = created;
      const signer_id =
        signerId ?? (await portalApi.registerSigner({ profile: created.profile })).signer_id;
      const signer = { ...fields, signer_id, lastUsedAt: Date.now() };
      rememberSigner(signer);
      onChosen(signer);
    } catch (failure) {
      setError(message(failure));
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="signer-heading">
      <h1 id="signer-heading" ref={heading} tabIndex={-1}>
        Sign in with…
      </h1>
      {signers.length === 0 ? (
        <p className="quiet">No signers on this browser yet. Add one to continue.</p>
      ) : (
        <ul className="choices">
          {signers.map((signer) => (
            <li key={signer.signer_id}>
              <button
                type="button"
                className="choice"
                disabled={busy}
                onClick={() => onChosen(signer)}
              >
                <span className={`badge badge-${signer.kind}`} aria-hidden="true" />
                <span className="choice-text">
                  <span className="choice-title">{signer.label}</span>
                  <span className="choice-detail mono">{signerDetail(signer.profile)}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        className="secondary"
        aria-expanded={adding}
        aria-controls="add-signer"
        onClick={() => setAdding(!adding)}
      >
        Add signer
      </button>
      <p>
        <button type="button" className="link" disabled={busy} onClick={() => add(identifyPasskey)}>
          Use a passkey from another device or browser
        </button>
      </p>
      {adding && (
        <ul id="add-signer" className="choices options" aria-label="Signer options">
          <li>
            <button
              type="button"
              className="choice"
              disabled={busy}
              onClick={() => add(() => createPasskey(signers))}
            >
              <span className="badge badge-passkey" aria-hidden="true" />
              <span className="choice-text">
                <span className="choice-title">New passkey</span>
                <span className="choice-detail">Face, fingerprint or device PIN</span>
              </span>
            </button>
          </li>
          {wallets.length === 0 ? (
            <li className="quiet">No browser wallet found.</li>
          ) : (
            wallets.map((wallet) => (
              <li key={wallet.info.uuid}>
                <button
                  type="button"
                  className="choice"
                  disabled={busy}
                  onClick={() => add(() => connectWallet(wallet))}
                >
                  <span className="badge badge-wallet" aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">{wallet.info.name}</span>
                    <span className="choice-detail">Connect wallet (no signature)</span>
                  </span>
                </button>
              </li>
            ))
          )}
          <li>
            <button type="button" className="choice" disabled aria-describedby="phone-soon">
              <span className="badge badge-phone" aria-hidden="true" />
              <span className="choice-text">
                <span className="choice-title">Phone</span>
                <span className="choice-detail" id="phone-soon">
                  Coming soon
                </span>
              </span>
            </button>
          </li>
        </ul>
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

function CancelButton({ onCancel, disabled }: { onCancel: () => void; disabled: boolean }) {
  return (
    <button type="button" className="cancel" disabled={disabled} onClick={onCancel}>
      Cancel and return to the app
    </button>
  );
}

const ROLE_LABEL: Readonly<Record<PortalAccount["role"], string>> = {
  root: "Owner",
  permission: "Signer",
};

function AccountStep({
  signer,
  rootOnly,
  onBack,
  onChosen,
  onCancel,
}: {
  signer: RememberedSigner;
  /** A grant is approved by an account's root: other memberships are not offered. */
  rootOnly: boolean;
  onBack: () => void;
  onChosen: (account: PortalAccount) => void;
  onCancel: () => void;
}) {
  const [accounts, setAccounts] = useState<readonly PortalAccount[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), []);
  useEffect(() => {
    portalApi.signerAccounts(signer.signer_id).then(
      (response) =>
        setAccounts(
          rootOnly
            ? response.accounts.filter((account) => account.role === "root")
            : response.accounts,
        ),
      (failure: unknown) => setError(message(failure)),
    );
  }, [signer.signer_id, rootOnly]);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const created = await portalApi.createAccount({ root_signer_id: signer.signer_id });
      setAccounts((current) => [
        ...(current ?? []).filter((account) => account.account_id !== created.account_id),
        { ...created, role: "root" },
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
            ? "This signer owns no account yet. Only an account's owner can approve app access."
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
                disabled={busy}
                aria-label={`Smart account ${account.address}, ${ROLE_LABEL[account.role]}`}
                onClick={() => onChosen(account)}
              >
                <span className="badge badge-account" aria-hidden="true" />
                <span className="choice-text">
                  <span className="choice-title mono">{shortAddress(account.address)}</span>
                  <span className="choice-detail">Smart account · {ROLE_LABEL[account.role]}</span>
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
        <button type="button" className="secondary" disabled aria-describedby="link-soon">
          Link to an existing account
        </button>
        <p className="choice-detail" id="link-soon">
          Linking an existing account is coming soon.
        </p>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <CancelButton onCancel={onCancel} disabled={busy} />
    </section>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <main className="frame">
      <div className="mark" aria-hidden="true">
        OAAth
      </div>
      {children}
    </main>
  );
}

function Notice({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section role="status">
      <h1>{title}</h1>
      <p className="quiet">{children}</p>
    </section>
  );
}
