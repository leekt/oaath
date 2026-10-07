/**
 * Adding a signer to an existing account, and the owner's members view.
 *
 * - The new signer asks from the sign-in popup (`LinkRequest`) and shares the
 *   approval link, as text or as a QR code drawn here.
 * - The account's owner opens `/link/{id}`, signs in, reviews the request and
 *   signs one OAAth membership approval (`membership.ts`). The new signer can
 *   then sign in as the account; it holds no on-chain authority.
 * - `/accounts` lists the owner's accounts and their members; the owner can
 *   suspend, restore, or remove a member. Nothing happens on-chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import { useEffect, useRef, useState } from "react";
import { encode } from "uqr";
import {
  type PortalAccount,
  PortalApiError,
  type PortalLink,
  type PortalMember,
  portalApi,
} from "./api.js";
import { signMembershipApproval } from "./membership.js";
import { Frame, message, Notice, SignerStep } from "./shared.js";
import { type RememberedSigner, rememberSigner, shortAddress, signerDetail } from "./signers.js";

const POLL_MS = 2_000;

function linkMessage(error: unknown): string {
  const code = error instanceof PortalApiError ? error.code : (error as { code?: string })?.code;
  switch (code) {
    case "relay_not_found":
      return "No OAAth account has that address.";
    case "relay_already_decided":
      return "This signer is already on that account, or the request was already decided.";
    case "relay_expired":
      return "This request has expired. Ask for a new link.";
    case "relay_forbidden":
      return "Only the account's owner can approve this request.";
    case "link-mismatch":
    case "link-invalid":
      return "OAAth sent a request that doesn't match what you were shown. Nothing was signed.";
    case "passkey-cancelled":
      return "The passkey prompt was dismissed.";
    case "root-unsupported":
      return "This signer can't approve here.";
    default:
      return message(error);
  }
}

const KIND_LABEL: Readonly<Record<string, string>> = {
  webauthn: "Passkey",
  p256: "Security key",
  ecdsa: "Wallet",
};

/** A QR code as plain SVG rectangles: no script, no network. */
function QrCode({ text, label }: { text: string; label: string }) {
  const { data, size } = encode(text, { ecc: "M", border: 2 });
  const cells: string[] = [];
  data.forEach((row, y) => {
    row.forEach((dark, x) => {
      if (dark) cells.push(`M${x} ${y}h1v1h-1z`);
    });
  });
  return (
    <svg
      className="qr"
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
    >
      <rect width={size} height={size} fill="#fff" />
      <path d={cells.join("")} fill="#000" />
    </svg>
  );
}

/** The signed-in signer asks an account's owner to add it. */
export function LinkRequest({
  signer,
  onApproved,
}: {
  signer: RememberedSigner;
  onApproved: () => void;
}) {
  const [address, setAddress] = useState("");
  const [label, setLabel] = useState(signer.label);
  const [linkId, setLinkId] = useState<string | null>(null);
  const [status, setStatus] = useState<PortalLink["status"]>("pending");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!linkId || status !== "pending") return;
    const timer = setInterval(() => {
      portalApi.link(linkId).then(
        (link) => {
          setStatus(link.status);
          if (link.status === "approved") onApproved();
        },
        // A dropped poll is retried on the next tick.
        () => {},
      );
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [linkId, status, onApproved]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await portalApi.createLink({
        signer_id: signer.signer_id,
        account: address.trim() as `0x${string}`,
        label: label.trim(),
      });
      setLinkId(created.link_id);
    } catch (failure) {
      setError(linkMessage(failure));
    }
    setBusy(false);
  }

  if (linkId) {
    const url = `${location.origin}/link/${linkId}`;
    return (
      <section id="link-request" aria-labelledby="link-share-heading" className="link-request">
        <h2 id="link-share-heading">Ask the account's owner to approve</h2>
        <p className="quiet">
          Open this link on a device signed in as the owner of{" "}
          <span className="mono">{shortAddress(address.trim().toLowerCase())}</span>.
        </p>
        <QrCode text={url} label="Approval link QR code" />
        <p className="mono link-url" id="link-url">
          {url}
        </p>
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
        <p className="quiet" aria-live="polite" id="link-status">
          {status === "pending" && "Waiting for the owner's approval…"}
          {status === "approved" && "Approved. Choose the account above."}
          {status === "rejected" && "The owner declined this request."}
          {status === "expired" && "This request expired. Start again."}
          {status === "removed" && "The owner removed this signer."}
        </p>
      </section>
    );
  }
  return (
    <form id="link-request" className="link-request" onSubmit={submit}>
      <h2>Link to an existing account</h2>
      <p className="quiet">
        The account's owner approves this signer with one signature. It can then sign in as the
        account; it can't move funds.
      </p>
      <label>
        Account address
        <input
          id="link-account"
          className="mono"
          required
          pattern="0x[0-9a-fA-F]{40}"
          autoComplete="off"
          spellCheck={false}
          value={address}
          onChange={(event) => setAddress(event.target.value)}
        />
      </label>
      <label>
        Name for this signer
        <input
          id="link-label"
          required
          maxLength={64}
          value={label}
          onChange={(event) => setLabel(event.target.value)}
        />
      </label>
      <button type="submit" className="primary" disabled={busy}>
        Request access
      </button>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

/** `/link/{id}`: the owner reviews and signs; the requester sees the status. */
export function LinkApproval({ linkId }: { linkId: string }) {
  const [signer, setSigner] = useState<RememberedSigner | null>(null);
  const [link, setLink] = useState<PortalLink | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    if (!signer) return;
    setFailure(null);
    portalApi
      .link(linkId)
      .then(setLink, (error: unknown) =>
        setFailure(
          error instanceof PortalApiError && error.status === 404
            ? "This request doesn't exist. Ask for a new link."
            : linkMessage(error),
        ),
      );
  }, [linkId, signer]);

  const changeSigner = () => {
    portalApi.signOut().catch(() => {});
    setLink(null);
    setFailure(null);
    setSigner(null);
  };

  return (
    <Frame>
      <header className="client">
        <p className="eyebrow">Add a signer</p>
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
      {signer && !failure && !link && (
        <p className="quiet" aria-live="polite">
          Loading request…
        </p>
      )}
      {signer &&
        link &&
        (link.signer.signer_id === signer.signer_id ? (
          <Notice title="Waiting for the owner">
            {link.status === "pending"
              ? "Share this page's link with the account's owner."
              : `This request is ${link.status}.`}
          </Notice>
        ) : (
          <LinkReview link={link} linkId={linkId} signer={signer} onChange={setLink} />
        ))}
    </Frame>
  );
}

function LinkReview({
  link,
  linkId,
  signer,
  onChange,
}: {
  link: PortalLink;
  linkId: string;
  signer: RememberedSigner;
  onChange: (link: PortalLink) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), []);

  async function run(decide: () => Promise<PortalLink>) {
    setBusy(true);
    setError(null);
    try {
      onChange(await decide());
      rememberSigner({ ...signer, lastUsedAt: Date.now() });
    } catch (failure) {
      setError(linkMessage(failure));
    }
    setBusy(false);
  }

  if (link.status !== "pending")
    return (
      <section aria-labelledby="link-heading">
        <h1 id="link-heading" ref={heading} tabIndex={-1}>
          {link.status === "approved" ? "Signer added" : `This request is ${link.status}`}
        </h1>
        {link.status === "approved" && (
          <p className="quiet">
            {link.label} can now sign in as{" "}
            <span className="mono">{shortAddress(link.address)}</span>.
          </p>
        )}
        <Members accountId={link.account_id} />
      </section>
    );
  const expires = new Date(link.expires_at * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  return (
    <section aria-labelledby="link-heading">
      <h1 id="link-heading" ref={heading} tabIndex={-1}>
        Add a signer to your account
      </h1>
      <dl className="review">
        <dt>Account</dt>
        <dd className="mono">{link.address}</dd>
        <dt>New signer</dt>
        <dd>
          {KIND_LABEL[link.signer.kind] ?? link.signer.kind} “{link.label}”
          <span className="choice-detail mono">{signerDetail(link.signer.profile)}</span>
        </dd>
        <dt>Request expires</dt>
        <dd>{expires}</dd>
      </dl>
      <fieldset className="access">
        <legend>Access</legend>
        <label>
          <input type="radio" name="access" defaultChecked />
          Sign in only
          <span className="choice-detail">
            Can sign in to apps as this account. Can't move funds or approve transactions.
          </span>
        </label>
        <label className="disabled">
          <input type="radio" name="access" disabled />
          Sign in and spend within a policy
          <span className="choice-detail">Coming soon</span>
        </label>
      </fieldset>
      <p className="quiet">You sign once with {signer.label}. Nothing is sent on-chain.</p>
      <div className="actions">
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() =>
            run(async () =>
              portalApi.approveLink(linkId, await signMembershipApproval(link, linkId, signer)),
            )
          }
        >
          Approve and sign
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => run(() => portalApi.rejectLink(linkId))}
        >
          Reject
        </button>
      </div>
      {busy && (
        <p className="quiet" aria-live="polite">
          Confirm with your passkey or wallet…
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

const ROLE_LABEL: Readonly<Record<PortalMember["role"], string>> = {
  root: "Owner",
  permission: "Signer",
};

/** The account's members, for its owner, with removal. */
type MemberAction = "suspend" | "restore" | "remove";

const CONFIRM: Readonly<Record<MemberAction, { label: string; note: string }>> = {
  suspend: {
    label: "Confirm suspension",
    note: "They can't sign in as this account, and its app access is cut off. Nothing changes on-chain.",
  },
  restore: {
    label: "Confirm restore",
    note: "They can sign in again. App access cut off by the suspension stays off.",
  },
  remove: { label: "Confirm removal", note: "They leave this account. Nothing changes on-chain." },
};

function Members({ accountId }: { accountId: string }) {
  const [members, setMembers] = useState<readonly PortalMember[] | null>(null);
  const [confirming, setConfirming] = useState<{
    readonly signerId: string;
    readonly action: MemberAction;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    portalApi.members(accountId).then(
      (response) => setMembers(response.members),
      (failure: unknown) => setError(linkMessage(failure)),
    );
  }, [accountId]);

  async function act(member: PortalMember, action: MemberAction) {
    setBusy(true);
    setError(null);
    try {
      if (action === "remove") {
        await portalApi.removeMember(accountId, member.signer_id);
        setMembers((current) =>
          (current ?? []).filter((entry) => entry.signer_id !== member.signer_id),
        );
      } else {
        const { status } = await portalApi.setMemberStatus(accountId, member.signer_id, action);
        setMembers((current) =>
          (current ?? []).map((entry) =>
            entry.signer_id === member.signer_id ? { ...entry, status } : entry,
          ),
        );
      }
    } catch (failure) {
      setError(linkMessage(failure));
    }
    setConfirming(null);
    setBusy(false);
  }

  return (
    <section aria-labelledby="members-heading" className="members">
      <h2 id="members-heading">Members</h2>
      {members === null && !error && (
        <p className="quiet" aria-live="polite">
          Loading members…
        </p>
      )}
      {members && (
        <ul className="choices">
          {members.map((member) => {
            const name =
              member.label ??
              (member.grant_id ? "App signer" : (KIND_LABEL[member.kind] ?? member.kind));
            const pending = confirming?.signerId === member.signer_id ? confirming.action : null;
            const toggle = member.status === "suspended" ? "restore" : "suspend";
            return (
              <li key={`${member.signer_id}:${member.link_id ?? member.grant_id ?? "root"}`}>
                <div className="choice member">
                  <span className="choice-text">
                    <span className="choice-title">
                      {name}
                      {member.status === "suspended" && (
                        <span className="status-badge"> Suspended</span>
                      )}
                    </span>
                    <span className="choice-detail">
                      {ROLE_LABEL[member.role]} · {KIND_LABEL[member.kind] ?? member.kind} ·{" "}
                      <span className="mono">{signerDetail(member.profile)}</span>
                    </span>
                  </span>
                  {member.role !== "root" && pending && (
                    <div className="member-actions">
                      <p className="choice-detail">{CONFIRM[pending].note}</p>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => act(member, pending)}
                      >
                        {CONFIRM[pending].label}
                      </button>
                      <button
                        type="button"
                        className="link"
                        disabled={busy}
                        onClick={() => setConfirming(null)}
                      >
                        Keep as is
                      </button>
                    </div>
                  )}
                  {member.role !== "root" && !pending && (
                    <div className="member-actions">
                      <button
                        type="button"
                        className="secondary"
                        disabled={busy}
                        aria-label={`${toggle === "suspend" ? "Suspend" : "Restore"} ${name}`}
                        onClick={() =>
                          setConfirming({ signerId: member.signer_id, action: toggle })
                        }
                      >
                        {toggle === "suspend" ? "Suspend" : "Restore"}
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={busy}
                        aria-label={`Remove ${name}`}
                        onClick={() =>
                          setConfirming({ signerId: member.signer_id, action: "remove" })
                        }
                      >
                        Remove
                      </button>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

/** `/accounts`: the owner's accounts and their members. */
export function ManageAccounts() {
  const [signer, setSigner] = useState<RememberedSigner | null>(null);
  const [accounts, setAccounts] = useState<readonly PortalAccount[] | null>(null);
  const [chosen, setChosen] = useState<PortalAccount | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!signer) return;
    portalApi.signerAccounts(signer.signer_id).then(
      (response) => setAccounts(response.accounts.filter((account) => account.role === "root")),
      (failure: unknown) => setError(linkMessage(failure)),
    );
  }, [signer]);

  return (
    <Frame>
      <header className="client">
        <p className="eyebrow">Your accounts</p>
      </header>
      {!signer && <SignerStep onChosen={setSigner} />}
      {signer && !chosen && (
        <section aria-labelledby="owned-heading">
          <h1 id="owned-heading">Accounts you own</h1>
          {accounts?.length === 0 && <p className="quiet">This signer owns no account.</p>}
          {accounts && accounts.length > 0 && (
            <ul className="choices">
              {accounts.map((account) => (
                <li key={account.account_id}>
                  <button
                    type="button"
                    className="choice"
                    aria-label={`Smart account ${account.address}`}
                    onClick={() => setChosen(account)}
                  >
                    <span className="badge badge-account" aria-hidden="true" />
                    <span className="choice-text">
                      <span className="choice-title mono">{shortAddress(account.address)}</span>
                      <span className="choice-detail">Smart account · Owner</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
      {chosen && (
        <section aria-labelledby="account-members-heading">
          <h1 id="account-members-heading" className="mono">
            {shortAddress(chosen.address)}
          </h1>
          <button type="button" className="link" onClick={() => setChosen(null)}>
            All accounts
          </button>
          <Members accountId={chosen.account_id} />
        </section>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </Frame>
  );
}
