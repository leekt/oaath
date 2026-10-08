/** OAuth app configuration owned by the freshly authenticated signer. */
import { Field } from "@base-ui/react/field";
import { Input } from "@base-ui/react/input";
import { Radio } from "@base-ui/react/radio";
import { RadioGroup } from "@base-ui/react/radio-group";
import { ArrowLeft, ArrowRight, Check, Copy, Plus } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { type OAuthClient, type OAuthClientInput, PortalApiError, portalApi } from "./api.js";
import { Button } from "./components/ui/button.js";
import { Frame, message, SignerStep } from "./shared.js";
import type { RememberedSigner } from "./signers.js";

export function Developers() {
  const [signer, setSigner] = useState<RememberedSigner | null>(null);
  const [clients, setClients] = useState<readonly OAuthClient[] | null>(null);
  const [editing, setEditing] = useState<OAuthClient | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (signer && !editing) heading.current?.focus();
  }, [signer, editing]);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setClients((await portalApi.clients()).clients);
    } catch (failure) {
      setError(message(failure));
    }
    setLoading(false);
  }

  function choose(chosen: RememberedSigner) {
    setSigner(chosen);
    void load();
  }

  async function signOut() {
    setLoading(true);
    try {
      await portalApi.signOut();
      setSigner(null);
      setClients(null);
      setEditing(null);
      setNotice("");
      setError(null);
    } catch (failure) {
      setError(message(failure));
    }
    setLoading(false);
  }

  if (!signer)
    return (
      <Frame>
        <header className="client">
          <p className="context-title">Developer console</p>
          <p>Connect your app to OAAth.</p>
          <p className="quiet">
            Create a client ID and manage your app's callback URLs. Your apps belong to the signer
            you choose.
          </p>
          <a href="/">Back to OAAth</a>
        </header>
        <SignerStep onChosen={choose} />
      </Frame>
    );

  return (
    <Frame variant="workspace">
      <div className="console-session">
        <span>Developer console</span>
        <Button variant="ghost" disabled={loading} onClick={signOut}>
          Sign out
        </Button>
      </div>
      {editing ? (
        <ClientEditor
          key={editing === "new" ? "new" : editing.client_id}
          client={editing === "new" ? null : editing}
          onBusyChange={setLoading}
          onBack={() => {
            setEditing(null);
            setNotice("");
          }}
          onSaved={(client) => {
            setClients((current) =>
              current?.some((item) => item.client_id === client.client_id)
                ? current.map((item) => (item.client_id === client.client_id ? client : item))
                : [...(current ?? []), client],
            );
            setEditing(null);
            setNotice(
              editing === "new"
                ? "App created. Open its settings to copy the client ID."
                : "Changes saved.",
            );
          }}
          onReload={() => {
            setEditing(null);
            void load();
          }}
        />
      ) : (
        <>
          <div className="workspace-title console-title">
            <div>
              <h1 ref={heading} tabIndex={-1}>
                Your apps
              </h1>
              <p className="quiet">Configure how your apps connect to OAAth.</p>
            </div>
            {clients && clients.length > 0 && (
              <Button disabled={loading} onClick={() => setEditing("new")}>
                <Plus size={18} aria-hidden="true" /> New app
              </Button>
            )}
          </div>
          {notice && (
            <p className="console-success" role="status">
              <Check size={18} aria-hidden="true" />
              {notice}
            </p>
          )}
          {loading && <p role="status">Loading your apps…</p>}
          {error && (
            <div role="alert">
              <p className="error">{error}</p>
              <Button variant="outline" disabled={loading} onClick={load}>
                Reload apps
              </Button>
            </div>
          )}
          {clients?.length === 0 && !loading && (
            <section className="console-empty">
              <h2>Your first connection starts here</h2>
              <p>
                Register an app to get a client ID. Add the callback URL where your app receives the
                sign-in result.
              </p>
              <Button onClick={() => setEditing("new")}>
                <Plus size={18} aria-hidden="true" /> Create app
              </Button>
            </section>
          )}
          {clients && clients.length > 0 && (
            <ul className="client-list" aria-label="Your OAuth apps">
              {clients.map((client) => (
                <li key={client.client_id}>
                  <Button
                    variant="ghost"
                    className="client-row"
                    disabled={loading}
                    onClick={() => {
                      setEditing(client);
                      setNotice("");
                    }}
                  >
                    <span className="client-row-main">
                      <span className="client-name">{client.client_name}</span>
                      <span className="quiet small">
                        {client.redirect_uris.length} callback{" "}
                        {client.redirect_uris.length === 1 ? "URL" : "URLs"} · Public client
                      </span>
                    </span>
                    <span className="client-row-origin mono">
                      {new URL(client.redirect_uris[0] ?? "https://oaath.taek.tech").host}
                    </span>
                    <ArrowRight size={19} aria-hidden="true" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <p className="console-ownership quiet small">
            Apps are saved to this signer. Use the same passkey or wallet to manage them on another
            device. Apps registered through the public API do not appear here.
          </p>
        </>
      )}
    </Frame>
  );
}

function ClientEditor({
  client,
  onBack,
  onSaved,
  onReload,
  onBusyChange,
}: {
  client: OAuthClient | null;
  onBack: () => void;
  onSaved: (client: OAuthClient) => void;
  onReload: () => void;
  onBusyChange: (busy: boolean) => void;
}) {
  const [name, setName] = useState(client?.client_name ?? "");
  const [redirects, setRedirects] = useState(client?.redirect_uris.join("\n") ?? "");
  const [delivery, setDelivery] = useState<OAuthClientInput["revocation_delivery"]>(
    client?.revocation_delivery ?? "relay",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    const uris = redirects
      .split(/\r?\n/u)
      .map((uri) => uri.trim())
      .filter(Boolean);
    if (!uris.length || uris.length > 8 || new Set(uris).size !== uris.length) {
      setError("Add 1–8 different callback URLs, one per line.");
      return;
    }
    if (!name.trim()) {
      setError("Enter an app name.");
      return;
    }
    setBusy(true);
    onBusyChange(true);
    try {
      const input = {
        client_name: name.trim(),
        redirect_uris: uris,
        revocation_delivery: delivery,
        token_endpoint_auth_method: "none" as const,
      };
      onSaved(
        client
          ? await portalApi.updateClient(client.client_id, input)
          : await portalApi.createClient(input),
      );
    } catch (failure) {
      if (failure instanceof PortalApiError && failure.code === "relay_request_invalid") {
        setError(
          "Check your callback URLs. Use an exact HTTPS URL, or HTTP on localhost or 127.0.0.1, without a fragment or credentials.",
        );
      } else if (failure instanceof PortalApiError && failure.code === "relay_not_found") {
        setError("This app is no longer available to this signer. Reload your apps.");
      } else {
        setError(message(failure));
        // A lost creation reply never automatically repeats the registration.
        setUncertain(!client && !(failure instanceof PortalApiError && failure.status === 401));
      }
    }
    setBusy(false);
    onBusyChange(false);
  }

  return (
    <section className="client-editor">
      <Button variant="ghost" className="console-back" disabled={busy} onClick={onBack}>
        <ArrowLeft size={17} aria-hidden="true" /> All apps
      </Button>
      <h1>{client ? "App settings" : "Create an app"}</h1>
      <p className="quiet">
        {client
          ? "Update how this app appears and where sign-in returns."
          : "Give your app a name and a place to return after sign-in."}
      </p>
      <div className="console-columns">
        <form onSubmit={save} className="client-form" aria-label="App configuration">
          <Field.Root className="console-field" disabled={busy}>
            <Field.Label>App name</Field.Label>
            <Input
              id="client-name"
              required
              maxLength={128}
              value={name}
              onValueChange={setName}
              autoFocus
              autoComplete="off"
            />
            <Field.Description>
              People see this name when they sign in to your app.
            </Field.Description>
          </Field.Root>
          <div className="console-field">
            <label htmlFor="client-redirects">Callback URLs</label>
            <textarea
              id="client-redirects"
              className="mono"
              rows={4}
              required
              disabled={busy}
              value={redirects}
              onChange={(event) => setRedirects(event.target.value)}
              aria-describedby="redirect-help"
              spellCheck={false}
              autoCapitalize="none"
              autoComplete="off"
              placeholder="https://your-app.com/callback"
            />
            <p id="redirect-help" className="field-help">
              One exact URL per line, up to 8. Use HTTPS, or HTTP on localhost or 127.0.0.1 for
              development. Wildcards and fragments are not supported.
            </p>
          </div>
          <fieldset className="console-delivery" disabled={busy}>
            <legend>Who submits revocations?</legend>
            <p className="field-help">
              The account owner always signs first. This chooses who submits the signed revocation
              on chain.
            </p>
            <RadioGroup
              value={delivery}
              onValueChange={setDelivery}
              disabled={busy}
              aria-label="Revocation delivery"
            >
              <label htmlFor="delivery-relay">
                <Radio.Root id="delivery-relay" value="relay" className="console-radio">
                  <Radio.Indicator />
                </Radio.Root>
                <span>
                  OAAth
                  <span className="choice-detail">OAAth submits it for the account owner.</span>
                </span>
              </label>
              <label htmlFor="delivery-dapp">
                <Radio.Root id="delivery-dapp" value="dapp" className="console-radio">
                  <Radio.Indicator />
                </Radio.Root>
                <span>
                  My app
                  <span className="choice-detail">
                    Your app must retrieve and submit it. The owner can still ask OAAth to submit.
                  </span>
                </span>
              </label>
            </RadioGroup>
          </fieldset>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {uncertain && (
            <p className="quiet small">
              The app may have been created. Reload your apps before creating another.
            </p>
          )}
          <div className="console-actions">
            {uncertain ? (
              <Button onClick={onReload}>Reload apps</Button>
            ) : (
              <Button type="submit" disabled={busy}>
                {busy ? "Saving…" : client ? "Save changes" : "Create app"}
              </Button>
            )}
            <Button variant="outline" disabled={busy} onClick={onBack}>
              Cancel
            </Button>
          </div>
        </form>
        <aside className="console-reference" aria-label="Integration details">
          <h2>{client ? "Connect this app" : "What you'll get"}</h2>
          {client ? (
            <>
              <label htmlFor="client-id">Client ID</label>
              <Input id="client-id" className="mono" readOnly value={client.client_id} />
              <Button
                variant="outline"
                onClick={() =>
                  navigator.clipboard.writeText(client.client_id).then(
                    () => setCopy("copied"),
                    () => setCopy("failed"),
                  )
                }
              >
                {copy === "copied" ? (
                  <Check size={16} aria-hidden="true" />
                ) : (
                  <Copy size={16} aria-hidden="true" />
                )}
                {copy === "copied" ? "Copied" : "Copy client ID"}
              </Button>
              <p className="field-help" role="status">
                {copy === "failed"
                  ? "Copy was unavailable. Select and copy the client ID above."
                  : "Use this ID in your app's OAAth configuration."}
              </p>
            </>
          ) : (
            <p>
              A client ID to identify your app during sign-in. You can copy it after creating the
              app.
            </p>
          )}
          <h3>Public client · PKCE</h3>
          <p>
            No client secret is issued. Your app uses the authorization code flow with PKCE (S256).
          </p>
          <details className="console-endpoints">
            <summary>OAuth endpoints</summary>
            <dl>
              <dt>Issuer</dt>
              <dd className="mono">{location.origin}</dd>
              <dt>Discovery</dt>
              <dd className="mono">/.well-known/openid-configuration</dd>
              <dt>Pushed authorization</dt>
              <dd className="mono">/oauth/par</dd>
              <dt>Token</dt>
              <dd className="mono">/oauth/token</dd>
            </dl>
          </details>
        </aside>
      </div>
    </section>
  );
}
