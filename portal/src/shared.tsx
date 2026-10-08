/**
 * Pieces every portal page shares: the frame, notices, error copy, QR codes, and the
 * signer step that ends in a fresh session for the chosen signer.
 *
 * @author taek <leekt216@gmail.com>
 */
import { ArrowLeft, Fingerprint, KeyRound, Plus, Trash2, Wallet } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { encode } from "uqr";
import { PortalApiError, portalApi } from "./api.js";
import { Button } from "./components/ui/button.js";
import { signInPasskey, signInUnknownPasskey, signInWallet } from "./session.js";
import {
  type AnnouncedWallet,
  connectWallet,
  createPasskey,
  forgetSigner,
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
  const [signers, setSigners] = useState(rememberedSigners);
  const [forgetting, setForgetting] = useState<string | null>(null);
  const [panel, setPanel] = useState<"methods" | "wallets" | "passkeys" | "add">("methods");
  const [back, setBack] = useState(false);
  const walletButton = useRef<HTMLButtonElement>(null);
  const passkeyButton = useRef<HTMLButtonElement>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<"wallets" | "passkeys" | "add" | null>(null);
  const [discovered, setDiscovered] = useState(false);
  const [wallets, setWallets] = useState<AnnouncedWallet[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (panel === "methods" && returnFocus.current) {
      const target =
        returnFocus.current === "wallets"
          ? walletButton
          : returnFocus.current === "passkeys"
            ? passkeyButton
            : addButton;
      target.current?.focus();
    } else heading.current?.focus();
  }, [panel]);
  useEffect(() => {
    const stop = watchWallets(setWallets);
    // Give asynchronously announcing extensions time before showing an empty state.
    const timer = setTimeout(() => setDiscovered(true), 600);
    return () => {
      stop();
      clearTimeout(timer);
    };
  }, []);

  // This navigation never signs in, registers a signer, or reads an account.
  function open(next: Exclude<typeof panel, "methods">) {
    returnFocus.current = panel === "add" ? "add" : next;
    setError(null);
    setForgetting(null);
    setBack(false);
    setPanel(next);
  }
  function goBack() {
    setError(null);
    setForgetting(null);
    setBack(true);
    setPanel("methods");
  }

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

  function forget(signerId: string) {
    try {
      setSigners(forgetSigner(signerId));
      setForgetting(null);
      heading.current?.focus();
    } catch {
      setError(
        "This browser couldn't forget the signer. Check your browser's storage settings and try again.",
      );
    }
  }

  const saved = signers.filter(
    (signer) => signer.kind === (panel === "wallets" ? "wallet" : "passkey"),
  );
  return (
    <section className="signer-step" aria-labelledby="signer-heading" aria-busy={busy}>
      <div className="method-panel" key={panel} data-direction={back ? "back" : "forward"}>
        {panel !== "methods" && (
          <Button variant="ghost" className="back" disabled={busy} onClick={goBack}>
            <ArrowLeft size={16} aria-hidden="true" /> Back
          </Button>
        )}
        <h1 id="signer-heading" ref={heading} tabIndex={-1}>
          {panel === "wallets"
            ? "Choose your wallet"
            : panel === "passkeys"
              ? "Use a passkey"
              : panel === "add"
                ? "Add a signer"
                : "How would you like to sign in?"}
        </h1>
        <p className="quiet">Your passkey or wallet confirms it's you. This approves nothing.</p>
        {panel === "methods" && (
          <>
            <ul className="choices method-choices" aria-label="Sign-in methods">
              <li>
                <Button
                  id="passkey-method"
                  ref={passkeyButton}
                  variant="choice"
                  disabled={busy}
                  onClick={() => open("passkeys")}
                >
                  <Fingerprint size={24} aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">Passkey</span>
                    <span className="choice-detail">Your face, fingerprint or device PIN</span>
                  </span>
                </Button>
              </li>
              <li>
                <Button
                  id="wallet-method"
                  ref={walletButton}
                  variant="choice"
                  disabled={busy}
                  onClick={() => open("wallets")}
                >
                  <Wallet size={24} aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">Wallet</span>
                    <span className="choice-detail">Choose a browser wallet</span>
                  </span>
                </Button>
              </li>
            </ul>
            {signers.length === 0 && (
              <p className="quiet small">No signers on this browser yet. Add one to continue.</p>
            )}
            <Button ref={addButton} variant="ghost" disabled={busy} onClick={() => open("add")}>
              <Plus size={16} aria-hidden="true" /> Add signer
            </Button>
          </>
        )}
        {(panel === "passkeys" || panel === "wallets") && saved.length > 0 && (
          <ul className="choices" aria-label="Saved signers">
            {saved.map((signer) => (
              <li key={signer.signer_id} className="saved-signer">
                <Button
                  variant="choice"
                  data-signer-kind={signer.kind}
                  disabled={busy}
                  onClick={() => run(() => signIn(signer))}
                >
                  <span className={`badge badge-${signer.kind}`} aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">{signer.label}</span>
                    <span className="choice-detail mono">{signerDetail(signer.profile)}</span>
                  </span>
                </Button>
                <Button
                  variant="ghost"
                  className="forget-signer"
                  disabled={busy}
                  aria-label={`Forget ${signer.label} from this browser`}
                  onClick={() => setForgetting(signer.signer_id)}
                >
                  <Trash2 size={17} aria-hidden="true" />
                </Button>
                {forgetting === signer.signer_id && (
                  <div className="forget-confirm">
                    <p>
                      Forget {signer.label} from this browser? This removes its saved entry only.
                      Its account access and the passkey or wallet itself stay unchanged.
                    </p>
                    <div className="actions">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setForgetting(null);
                          heading.current?.focus();
                        }}
                      >
                        Keep signer
                      </Button>
                      <Button onClick={() => forget(signer.signer_id)}>Forget signer</Button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
        {(panel === "passkeys" || panel === "add") && (
          <ul className="choices" aria-label="Add signer">
            <li>
              <Button
                variant="choice"
                disabled={busy}
                onClick={() => run(() => add(() => createPasskey(signers)))}
              >
                <Fingerprint size={24} aria-hidden="true" />
                <span className="choice-text">
                  <span className="choice-title">New passkey</span>
                  <span className="choice-detail">Save a passkey to this device</span>
                </span>
              </Button>
            </li>
            {panel === "add" && (
              <li>
                <Button
                  id="add-wallet-method"
                  variant="choice"
                  disabled={busy}
                  onClick={() => open("wallets")}
                >
                  <Wallet size={24} aria-hidden="true" />
                  <span className="choice-text">
                    <span className="choice-title">Wallet</span>
                    <span className="choice-detail">Connect a browser wallet</span>
                  </span>
                </Button>
              </li>
            )}
          </ul>
        )}
        {panel === "wallets" && (
          <>
            {saved.length > 0 && <h2 className="list-heading">Connect a wallet</h2>}
            {wallets.length === 0 ? (
              <p className="empty-state">
                {discovered
                  ? "No browser wallet found. Open your wallet's browser, or return to use a passkey."
                  : "Looking for browser wallets…"}
              </p>
            ) : (
              <ul className="choices" aria-label="Available wallets">
                {wallets.map((wallet) => (
                  <li key={wallet.info.uuid}>
                    <Button
                      variant="choice"
                      disabled={busy}
                      onClick={() => run(() => add(() => connectWallet(wallet), wallet))}
                    >
                      <Wallet size={24} aria-hidden="true" />
                      <span className="choice-text">
                        <span className="choice-title">{wallet.info.name}</span>
                        <span className="choice-detail">Sign in with your wallet</span>
                      </span>
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
        {panel !== "wallets" && (
          <p className="cross-device">
            <Button variant="ghost" disabled={busy} onClick={() => run(recognise)}>
              Use a passkey from another device or browser
            </Button>
          </p>
        )}
      </div>
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

export function Frame({
  children,
  variant = "auth",
}: {
  children: React.ReactNode;
  variant?: "auth" | "workspace" | "landing";
}) {
  return (
    <div className={`shell shell-${variant}`}>
      <header className="masthead">
        {variant === "auth" ? (
          <span className="mark">
            <KeyRound aria-hidden="true" /> OAAth
          </span>
        ) : (
          <a className="mark" href="/" aria-label="OAAth home">
            <KeyRound aria-hidden="true" /> OAAth
          </a>
        )}
        {variant === "auth" ? (
          <span className="quiet small">Account portal</span>
        ) : (
          <nav aria-label="Portal">
            <a
              href="/accounts"
              aria-current={location.pathname === "/accounts" ? "page" : undefined}
            >
              Accounts
            </a>
            <a
              href="/developers"
              aria-current={location.pathname === "/developers" ? "page" : undefined}
            >
              Developers
            </a>
          </nav>
        )}
      </header>
      <main className={`frame frame-${variant}`}>{children}</main>
      <footer className="site-footer">
        <span>OAAth · Your account, your choice.</span>
        <span>Proof of concept</span>
      </footer>
    </div>
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
