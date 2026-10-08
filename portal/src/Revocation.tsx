/**
 * Removing an invalidated grant's permission on chain: the account root signs
 * one owner operation that uninstalls it, and OAAth submits it (or the dapp
 * does, when it opted in). The portal signs only an uninstall of exactly this
 * grant's install packages on the chosen account.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeKernelPermissionUninstallCalls } from "@oaath/protocol";
import { ECDSA_VALIDATOR, kernelKey } from "@oaath/sdk/kernel";
import { useCallback, useEffect, useState } from "react";
import { type PortalAccount, PortalApiError, portalApi, type RevocationView } from "./api.js";
import { reviewedOperation, signOperation } from "./operation-signing.js";
import { RootSigningError } from "./root-signing.js";
import { message } from "./shared.js";
import { type RememberedSigner, shortAddress } from "./signers.js";

const POLL_MS = 3_000;
/** Status reads while an operation is on its way; each may spend one bundler request. */
const MAX_POLLS = 20;

const STATUS: Readonly<Record<RevocationView["status"], string>> = {
  not_installed: "Not installed on chain: nothing to revoke.",
  pending_signature: "Still installed on chain.",
  submitted: "Revocation submitted; waiting for inclusion…",
  delivered: "Signed; the app submits the revocation.",
  included: "Revocation included; waiting for finality…",
  finalized: "Revoked on chain.",
  failed: "The revocation did not go through.",
};

function failure(error: unknown): string {
  const code =
    error instanceof RootSigningError || error instanceof PortalApiError
      ? error.code
      : (error as { code?: string })?.code;
  switch (code) {
    case "request-mismatch":
    case "request-invalid":
    case "calls-mismatch":
      return "OAAth sent an operation that doesn't match this grant. Nothing was signed.";
    case "relay_chain_unavailable":
      return "The chain or the bundler is unavailable. Try again later.";
    case "relay_request_budget_exhausted":
      return "This revocation has used its request budget.";
    default:
      return message(error);
  }
}

/** One grant's on-chain revocation: its status, and the root's one signature. */
export function RevokeOnChain({
  grantId,
  account,
  signer,
}: {
  grantId: string;
  account: PortalAccount;
  signer: RememberedSigner;
}) {
  const [view, setView] = useState<RevocationView | null>(null);
  const [confirming, setConfirming] = useState(false);
  /** For a dapp-delivered revocation: OAAth submits it now as well. */
  const [submitFromOaath, setSubmitFromOaath] = useState(false);
  const [busy, setBusy] = useState(false);
  const [polls, setPolls] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    () => portalApi.revocation(grantId).then(setView, (cause: unknown) => setError(failure(cause))),
    [grantId],
  );
  useEffect(() => {
    load();
  }, [load]);
  // Bounded polling while the operation travels.
  useEffect(() => {
    if (!view || !["submitted", "delivered", "included"].includes(view.status)) return;
    if (polls >= MAX_POLLS) return;
    const timer = setTimeout(() => {
      setPolls((count) => count + 1);
      load();
    }, POLL_MS);
    return () => clearTimeout(timer);
  }, [view, polls, load]);

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      const estimation = kernelKey({
        credential: signer.profile,
        validator: signer.profile.kind === "ecdsa" ? ECDSA_VALIDATOR : null,
      }).dummySignature;
      const prepared = await portalApi.prepareRevocation(grantId, estimation);
      if (prepared.status !== "pending_signature" || !prepared.request) {
        setView(prepared);
      } else {
        const request = reviewedOperation({ request: prepared.request, signer, account });
        const expected = encodeKernelPermissionUninstallCalls({
          account: account.address,
          packages: prepared.packages as never,
        });
        if (JSON.stringify(request.calls) !== JSON.stringify(expected))
          throw new RootSigningError("calls-mismatch");
        const signature = await signOperation(request, signer);
        setView(await portalApi.signRevocation(grantId, signature, submitFromOaath));
        setPolls(0);
      }
    } catch (cause) {
      setError(failure(cause));
    }
    setConfirming(false);
    setBusy(false);
  }

  return (
    <div className="member-actions">
      <p className="choice-detail" aria-live="polite" data-revocation={view?.status ?? ""}>
        Grant <span className="mono">{shortAddress(grantId)}</span>:{" "}
        {view ? STATUS[view.status] : "Checking on chain…"}
      </p>
      {view?.status === "pending_signature" && !confirming && (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => setConfirming(true)}
        >
          Revoke on chain
        </button>
      )}
      {view?.status === "pending_signature" && confirming && (
        <>
          <p className="choice-detail">
            You sign one operation that removes this permission from the account.
            {view.delivery === "dapp" && !submitFromOaath
              ? " The app submits it."
              : " OAAth submits it."}
          </p>
          {view.delivery === "dapp" && (
            <label className="choice-detail">
              <input
                type="checkbox"
                checked={submitFromOaath}
                disabled={busy}
                onChange={(event) => setSubmitFromOaath(event.target.checked)}
              />{" "}
              Submit this revocation from OAAth now
            </label>
          )}
          <button type="button" className="danger" disabled={busy} onClick={revoke}>
            Confirm and sign
          </button>
          <button
            type="button"
            className="link"
            disabled={busy}
            onClick={() => setConfirming(false)}
          >
            Not now
          </button>
        </>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
