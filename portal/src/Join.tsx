import { useState } from "react";
import { portalApi, type PortalLink } from "./api.js";
import { Frame, SignerStep, Notice, message } from "./shared.js";
import { Button } from "./schematic/components";
import type { RememberedSigner } from "./signers.js";
import { membershipContext, returnMembership } from "./membership-handoff.js";

/** Keyline supplies the account; the recipient proves their signer here. */
export function Join() {
  const [context] = useState(() => membershipContext(location.hash));
  const [signer, setSigner] = useState<RememberedSigner | null>(null);
  const [link, setLink] = useState<PortalLink | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function continueToApp() {
    if (!context || !signer) return;
    setBusy(true);
    setError("");
    try {
      let current = link;
      const saved = sessionStorage.getItem(`oaath.join.${context.state}`);
      if (!current && saved) current = await portalApi.link(saved);
      if (!current) {
        const created = await portalApi.createLink({
          signer_id: signer.signer_id,
          account: context.account,
          label: context.label,
        });
        sessionStorage.setItem(`oaath.join.${context.state}`, created.link_id);
        current = await portalApi.link(created.link_id);
      }
      setLink(current);
      returnMembership(context, current);
    } catch (failure) {
      setError(message(failure));
    }
    setBusy(false);
  }
  if (!context)
    return (
      <Frame>
        <Notice title="This invite is incomplete">
          Return to Keyline and open the invite again.
        </Notice>
      </Frame>
    );
  return (
    <Frame>
      <header className="client">
        <h1>Set up your access</h1>
        <p>
          Choose or create a passkey or wallet. The account owner will review your request next.
        </p>
        <dl className="review">
          <dt>Account</dt>
          <dd className="mono">{context.account}</dd>
          <dt>Your name</dt>
          <dd>{context.label}</dd>
          <dt>Return to</dt>
          <dd>{new URL(context.origin).host}</dd>
        </dl>
      </header>
      {!signer ? (
        <SignerStep onChosen={setSigner} />
      ) : (
        <section>
          <h2>Your signer is ready</h2>
          <p>
            {signer.label} will be used for this account. Continue to get the link to send its
            owner.
          </p>
          <p className="quiet">
            The owner approves membership in OAAth. This step cannot move funds.
          </p>
          <Button variant="primary" disabled={busy} onClick={() => void continueToApp()}>
            {busy ? "Creating request…" : "Continue to Keyline"}
          </Button>
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
