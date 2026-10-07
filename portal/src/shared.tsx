/**
 * Pieces every portal page shares: the frame, notices, error copy, QR codes, and the
 * signer step that ends in a fresh session for the chosen signer.
 *
 * @author taek <leekt216@gmail.com>
 */
import { useEffect, useRef, useState } from "react";
import { encode } from "uqr";
import { PortalApiError, portalApi } from "./api.js";
import { signInPasskey, signInUnknownPasskey, signInWallet } from "./session.js";
import {
  type AnnouncedWallet,
  connectWallet,
  createPasskey,
  type NewSigner,
  type RememberedSigner,
  rememberedSigners,
  rememberSigner,
  signerDetail,
  watchWallets,
} from "./signers.js";

export function message(error: unknown): string {
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
    case "wallet-unavailable":
      return "Your wallet isn't available. Open it and try again.";
    case "wallet-declined":
      return "The sign-in was declined in your wallet.";
    case "wallet-account-mismatch":
      return "Your wallet is on another account. Switch to this signer's account and try again.";
    case "sign-in-refused":
      return "OAAth couldn't verify that sign-in. Please try again.";
    case "relay_membership_suspended":
      return "The account's owner suspended this signer. Ask them to restore it.";
    case "relay_unauthenticated":
      return "Your sign-in expired. Choose your signer again.";
    default:
      return "Something went wrong. Please try again.";
  }
}

export function SignerStep({
  onChosen,
  onCancel,
}: {
  onChosen: (signer: RememberedSigner) => void;
  /** Present inside an app's sign-in; a portal page has no app to return to. */
  onCancel?: () => void;
}) {
  const [signers] = useState(rememberedSigners);
  const [adding, setAdding] = useState(false);
  const [wallets, setWallets] = useState<AnnouncedWallet[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => heading.current?.focus(), []);
  useEffect(() => (adding ? watchWallets(setWallets) : undefined), [adding]);

  /** Every path ends in a fresh session for the chosen signer. */
  async function run(choose: () => Promise<RememberedSigner | null>) {
    setBusy(true);
    setError(null);
    try {
      const signer = await choose();
      if (!signer) throw Object.assign(new Error("unknown passkey"), { code: "passkey-unknown" });
      rememberSigner(signer);
      onChosen(signer);
    } catch (failure) {
      setError(message(failure));
      setBusy(false);
    }
  }

  async function signIn(signer: RememberedSigner, wallet: AnnouncedWallet | null = null) {
    if (signer.profile.kind === "ecdsa")
      await signInWallet(signer.signer_id, signer.profile.address, wallet, signer.rdns);
    else await signInPasskey(signer.signer_id, signer);
    return { ...signer, lastUsedAt: Date.now() };
  }

  async function add(create: () => Promise<NewSigner>, wallet: AnnouncedWallet | null = null) {
    const created = await create();
    const { signer_id } = await portalApi.registerSigner({ profile: created.profile });
    return signIn({ ...created, signer_id, lastUsedAt: Date.now() }, wallet);
  }

  async function recognise() {
    const found = await signInUnknownPasskey();
    if (!found) return null;
    const { signerId, ...fields } = found;
    return { ...fields, signer_id: signerId, lastUsedAt: Date.now() };
  }

  return (
    <section aria-labelledby="signer-heading">
      <h1 id="signer-heading" ref={heading} tabIndex={-1}>
        Sign in with…
      </h1>
      <p className="quiet">Your passkey or wallet confirms it's you. This approves nothing.</p>
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
                onClick={() => run(() => signIn(signer))}
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
        <button type="button" className="link" disabled={busy} onClick={() => run(recognise)}>
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
              onClick={() => run(() => add(() => createPasskey(signers)))}
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
                  onClick={() => run(() => add(() => connectWallet(wallet), wallet))}
                >
                  <span className="badge badge-wallet" aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">{wallet.info.name}</span>
                    <span className="choice-detail">Sign in with your wallet</span>
                  </span>
                </button>
              </li>
            ))
          )}
        </ul>
      )}
      {busy && (
        <p className="quiet" aria-live="polite">
          Confirm the sign-in with your passkey or wallet…
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {onCancel && <CancelButton onCancel={onCancel} disabled={busy} />}
    </section>
  );
}

export function CancelButton({ onCancel, disabled }: { onCancel: () => void; disabled: boolean }) {
  return (
    <button type="button" className="cancel" disabled={disabled} onClick={onCancel}>
      Cancel and return to the app
    </button>
  );
}

export function Frame({ children }: { children: React.ReactNode }) {
  return (
    <>
      <div className="masthead" aria-hidden="true">
        <span className="mark">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle className="mark-bow" cx="7" cy="12" r="5.5" />
            <circle className="mark-cut" cx="7" cy="12" r="2" />
            <path
              className="mark-blade"
              d="M12 10.75h10v2.5h-1V16h-1.75v-2.75h-1.75v3.75h-1.75v-3.75H12z"
            />
          </svg>
          OAAth
        </span>
      </div>
      <main className="frame">{children}</main>
    </>
  );
}

export function Notice({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section role="status">
      <h1>{title}</h1>
      <p className="quiet">{children}</p>
    </section>
  );
}

/** A QR code as plain SVG rectangles: no script, no network. */
export function QrCode({ text, label }: { text: string; label: string }) {
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
