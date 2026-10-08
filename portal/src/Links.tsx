/**
 * Adding a signer to an existing account, and the owner's members view.
 *
 * - The new signer asks from the sign-in popup (`LinkRequest`) and shares the
 *   approval link, as text or as a QR code drawn here.
 * - The account's owner opens `/link/{id}`, signs in, reviews the request and
 *   signs one OAAth membership approval (`membership.ts`). The new signer can
 *   then sign in as the account; it holds no on-chain authority.
 * - `/accounts` lists the owner's accounts and their members; the owner can
 *   suspend, restore, or remove a member (nothing happens on-chain), and
 *   decide members' pending app requests (`Requests.tsx`).
 *
 * @author taek <leekt216@gmail.com>
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type PolicyTemplate,
  type PortalAccount,
  PortalApiError,
  type PortalLink,
  type PortalMember,
  portalApi,
} from "./api.js";
import { signMemberGrant, signMembershipApproval } from "./membership.js";
import { Policies, templateSummary } from "./Policies.js";
import { PendingRequests } from "./Requests.js";
import { RevokeOnChain } from "./Revocation.js";
import { Frame, message, Notice, QrCode, SignerStep } from "./shared.js";
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
    case "grant-mismatch":
    case "grant-invalid":
    case "digest-mismatch":
      return "OAAth sent a request that doesn't match what you were shown. Nothing was signed.";
    case "account-unreadable":
      return "The account could not be read on Arbitrum Sepolia, so nothing was signed. Try again.";
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
    <Frame variant={link?.status === "approved" ? "workspace" : "auth"}>
      {link?.status !== "approved" && (
        <header className="client">
          <p className="context-title">Add a signer</p>
        </header>
      )}
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
  const [account, setAccount] = useState<PortalAccount | null>(null);
  const [templates, setTemplates] = useState<readonly PolicyTemplate[]>([]);
  /** "login" or the template the member is given. */
  const [access, setAccess] = useState("login");
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), []);
  useEffect(() => {
    portalApi.signerAccounts(signer.signer_id).then(
      (response) =>
        setAccount(response.accounts.find((entry) => entry.account_id === link.account_id) ?? null),
      () => {},
    );
    portalApi.policies(link.account_id).then(
      (response) => setTemplates(response.policies),
      () => {},
    );
  }, [signer.signer_id, link.account_id]);
  // A raw P-256 key has no operator kind: it can only sign in.
  const policyCapable = link.signer.kind !== "p256";

  async function approve(): Promise<PortalLink> {
    const template = templates.find((entry) => entry.template_id === access);
    if (!template)
      return portalApi.approveLink(linkId, await signMembershipApproval(link, linkId, signer));
    if (!account) throw new Error("account unavailable");
    const prepared = await portalApi.prepareLinkGrant(linkId, template.template_id);
    const artifact = await signMemberGrant({
      prepared,
      member: link.signer.profile,
      template,
      account,
      signer,
    });
    return portalApi.approveLinkWithTemplate(linkId, template.template_id, artifact);
  }

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
        {account && <Members account={account} signer={signer} />}
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
          <input
            type="radio"
            name="access"
            checked={access === "login"}
            onChange={() => setAccess("login")}
          />
          Sign in only
          <span className="choice-detail">
            Can sign in to apps as this account. Can't move funds or approve transactions.
          </span>
        </label>
        {templates.map((template) => (
          <label key={template.template_id} className={policyCapable ? undefined : "disabled"}>
            <input
              type="radio"
              name="access"
              disabled={!policyCapable}
              checked={access === template.template_id}
              onChange={() => setAccess(template.template_id)}
            />
            Sign in and spend within “{template.name}”
            <span className="choice-detail">{templateSummary(template)}</span>
          </label>
        ))}
        {templates.length === 0 && (
          <p className="choice-detail">
            Add a policy under Your accounts to let a signer spend within limits.
          </p>
        )}
        {!policyCapable && templates.length > 0 && (
          <p className="choice-detail">This kind of key can only sign in.</p>
        )}
      </fieldset>
      <p className="quiet">
        You sign once with {signer.label}. Nothing is sent on-chain
        {access === "login" ? "." : "; the signer's first payment installs the policy."}
      </p>
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={() => run(approve)}>
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
    note: "They can't sign in as this account, and its app access is cut off. Revoke on chain afterwards to remove it there too.",
  },
  restore: {
    label: "Confirm restore",
    note: "They can sign in again. App access cut off by the suspension stays off.",
  },
  remove: {
    label: "Confirm removal",
    note: "They leave this account. Revoke on chain afterwards to remove its app access there too.",
  },
};

/** One signer of the account, with every membership that admitted it. */
interface MemberEntry {
  readonly signer_id: string;
  readonly name: string;
  readonly member: PortalMember;
  /** Grants the signer holds on the account (dapp or template). */
  readonly grants: number;
  readonly grantIds: readonly string[];
}

function entries(members: readonly PortalMember[]): MemberEntry[] {
  const bySigner = new Map<string, PortalMember[]>();
  for (const member of members)
    bySigner.set(member.signer_id, [...(bySigner.get(member.signer_id) ?? []), member]);
  return [...bySigner.values()].map((rows) => {
    const [first] = rows as [PortalMember, ...PortalMember[]];
    const label = rows.find((row) => row.label !== null)?.label ?? null;
    return {
      signer_id: first.signer_id,
      name:
        label ??
        (rows.every((row) => row.grant_id) ? "App signer" : (KIND_LABEL[first.kind] ?? first.kind)),
      member: rows.find((row) => row.role === "root") ?? first,
      grants: rows.filter((row) => row.grant_id !== null).length,
      grantIds: rows.flatMap((row) => (row.grant_id === null ? [] : [row.grant_id])),
    };
  });
}

/** The account's members and policies, for its owner. */
function Members({ account, signer }: { account: PortalAccount; signer: RememberedSigner }) {
  const accountId = account.account_id;
  const [members, setMembers] = useState<readonly PortalMember[] | null>(null);
  const [templates, setTemplates] = useState<readonly PolicyTemplate[]>([]);
  const [confirming, setConfirming] = useState<{
    readonly signerId: string;
    readonly action: MemberAction;
  } | null>(null);
  const [assigning, setAssigning] = useState<Readonly<Record<string, string>>>({});
  /** Grants cut off here this visit (a removed member is no longer listed). */
  const [cutOff, setCutOff] = useState<readonly string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    () =>
      portalApi.members(accountId).then(
        (response) => setMembers(response.members),
        (failure: unknown) => setError(linkMessage(failure)),
      ),
    [accountId],
  );
  useEffect(() => {
    load();
    portalApi.policies(accountId).then(
      (response) => setTemplates(response.policies),
      (failure: unknown) => setError(linkMessage(failure)),
    );
  }, [accountId, load]);

  async function run(work: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await work();
      await load();
    } catch (failure) {
      setError(linkMessage(failure));
    }
    setConfirming(null);
    setBusy(false);
  }

  function act(member: PortalMember, action: MemberAction) {
    const grantIds = (members ?? []).flatMap((row) =>
      row.signer_id === member.signer_id && row.grant_id !== null ? [row.grant_id] : [],
    );
    return run(async () => {
      await (action === "remove"
        ? portalApi.removeMember(accountId, member.signer_id)
        : portalApi.setMemberStatus(accountId, member.signer_id, action));
      if (action !== "restore") setCutOff((current) => [...new Set([...current, ...grantIds])]);
    });
  }

  /** A fresh grant from a template: the owner signs the member's enable once. */
  function assign(member: PortalMember, templateId: string) {
    const template = templates.find((entry) => entry.template_id === templateId);
    if (!template) return;
    return run(async () => {
      const prepared = await portalApi.prepareAssignment(
        accountId,
        member.signer_id,
        template.template_id,
      );
      const artifact = await signMemberGrant({
        prepared,
        member: member.profile,
        template,
        account,
        signer,
      });
      await portalApi.assignGrant(accountId, member.signer_id, {
        template_id: template.template_id,
        request_id: prepared.permission_request.requestId,
        requested_at: prepared.permission_request.requestedAt,
        artifact,
      });
    });
  }

  return (
    <>
      <PendingRequests account={account} signer={signer} onDecided={load} />
      <section aria-labelledby="members-heading" className="members">
        <h2 id="members-heading">Members</h2>
        {members === null && !error && (
          <p className="quiet" aria-live="polite">
            Loading members…
          </p>
        )}
        {members && (
          <ul className="choices">
            {entries(members).map(({ signer_id, name, member, grants }) => {
              const pending = confirming?.signerId === signer_id ? confirming.action : null;
              const toggle = member.status === "suspended" ? "restore" : "suspend";
              const assignable =
                member.role !== "root" &&
                member.status === "active" &&
                member.kind !== "p256" &&
                templates.length > 0;
              return (
                <li key={signer_id}>
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
                        {grants > 0 && ` · ${grants} polic${grants === 1 ? "y" : "ies"}`}
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
                          onClick={() => setConfirming({ signerId: signer_id, action: toggle })}
                        >
                          {toggle === "suspend" ? "Suspend" : "Restore"}
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          disabled={busy}
                          aria-label={`Remove ${name}`}
                          onClick={() => setConfirming({ signerId: signer_id, action: "remove" })}
                        >
                          Remove
                        </button>
                      </div>
                    )}
                    {assignable && !pending && (
                      <div className="member-actions">
                        <select
                          aria-label={`Policy for ${name}`}
                          value={assigning[signer_id] ?? ""}
                          onChange={(event) =>
                            setAssigning({ ...assigning, [signer_id]: event.target.value })
                          }
                        >
                          <option value="">Choose a policy…</option>
                          {templates.map((template) => (
                            <option key={template.template_id} value={template.template_id}>
                              {template.name}
                            </option>
                          ))}
                        </select>
                        <button
                          type="button"
                          className="secondary"
                          disabled={busy || !assigning[signer_id]}
                          onClick={() => assign(member, assigning[signer_id] ?? "")}
                        >
                          Give policy and sign
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
      <RevocationList
        grantIds={[
          ...new Set([
            ...cutOff,
            ...(members ?? []).flatMap((row) =>
              row.status === "suspended" && row.grant_id !== null ? [row.grant_id] : [],
            ),
          ]),
        ]}
        account={account}
        signer={signer}
      />
      <Policies accountId={accountId} templates={templates} onChange={setTemplates} />
    </>
  );
}

/** Grants cut off off-chain whose permission may still be installed on chain. */
function RevocationList({
  grantIds,
  account,
  signer,
}: {
  grantIds: readonly string[];
  account: PortalAccount;
  signer: RememberedSigner;
}) {
  if (grantIds.length === 0) return null;
  return (
    <section aria-labelledby="revocations-heading" className="members">
      <h2 id="revocations-heading">On-chain revocation</h2>
      {grantIds.map((grantId) => (
        <RevokeOnChain key={grantId} grantId={grantId} account={account} signer={signer} />
      ))}
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
      (response) => {
        const owned = response.accounts.filter((account) => account.role === "root");
        setAccounts(owned);
        const requested = new URLSearchParams(location.search).get("account")?.toLowerCase();
        if (requested) setChosen(owned.find((account) => account.address === requested) ?? null);
      },
      (failure: unknown) => setError(linkMessage(failure)),
    );
  }, [signer]);

  return (
    <Frame variant={signer ? "workspace" : "auth"}>
      {!signer && (
        <header className="client">
          <p className="context-title">Your accounts, in one place.</p>
          <p className="quiet">Manage members, review app requests and set the access you share.</p>
        </header>
      )}
      {!signer && <SignerStep onChosen={setSigner} />}
      {signer && !chosen && (
        <section aria-labelledby="owned-heading">
          <h1 id="owned-heading">Accounts you own</h1>
          <p className="quiet">Choose an account to manage its members, policies and app access.</p>
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
                      <span className="choice-detail">
                        Smart account · Owner{"address" in account.profile && " · Imported"}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
      {chosen && signer && (
        <section aria-labelledby="account-members-heading">
          <div className="workspace-title">
            <div>
              <h1 id="account-members-heading">Account settings</h1>
              <p className="quiet mono">{shortAddress(chosen.address)}</p>
            </div>
            <span className="role-label">Owner</span>
          </div>
          <button type="button" className="link" onClick={() => setChosen(null)}>
            All accounts
          </button>
          <Members account={chosen} signer={signer} />
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
