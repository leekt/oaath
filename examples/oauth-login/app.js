/**
 * The dapp page: one "Login with OAAth" button. The client is registered with
 * the issuer once per browser (or configured), before any click, so the login
 * popup opens directly inside the user's gesture.
 */
import { loginWithOAAth } from "@oaath/sdk";

const { issuer, clientId: configuredClientId } = await (await fetch("/config.json")).json();
const redirectUri = `${location.origin}/callback`;
const button = document.querySelector("#login");
const result = document.querySelector("#result");
const status = document.querySelector("#status");

async function clientId() {
  if (configuredClientId) return configuredClientId;
  const key = `oaath-example-client:${issuer}:${redirectUri}`;
  const stored = localStorage.getItem(key);
  if (stored) return stored;
  // Dynamic client registration: public client, this page's redirect URI only.
  const response = await fetch(`${issuer}/oauth/clients`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "OAAth login example", redirect_uris: [redirectUri] }),
  });
  if (!response.ok) throw new Error(`client registration failed (${response.status})`);
  const registered = (await response.json()).client_id;
  localStorage.setItem(key, registered);
  return registered;
}

const client = await clientId();
status.textContent = `Issuer ${issuer} · client ${client}`;
button.disabled = false;
button.addEventListener("click", async () => {
  button.disabled = true;
  result.textContent = "";
  try {
    const login = await loginWithOAAth({ issuer, clientId: client, redirectUri });
    result.dataset.outcome = "signed-in";
    result.textContent = JSON.stringify(
      { account: login.account, signer: login.signer, verified: login.verified },
      null,
      2,
    );
    window.oaathLogin = login;
  } catch (error) {
    result.dataset.outcome = error.code ?? "error";
    result.textContent = `${error.code ?? "error"}: ${error.message}`;
  }
  button.disabled = false;
});
