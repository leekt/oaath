/**
 * Login with OAAth: OpenID Connect through the issuer's portal popup.
 *
 * ```text
 * loginWithOAAth()   opens a blank popup at once (inside the user's click)
 *                    PKCE + state + nonce; POST /oauth/par (scope=openid)
 *                    popup -> {issuer}/authorize: the user picks a signer and
 *                    an account; nothing is signed
 *                    the dapp's redirect page posts its URL back
 *                    (completeOAAthLogin); event origin, state and RFC 9207
 *                    `iss` are checked; POST /oauth/token
 *                    id_token verified against {issuer}/oauth/jwks (ES256,
 *                    iss, aud = clientId, nonce)
 * ```
 *
 * The result names the account and signer the user chose, and every account
 * the signer is an active member of. It is identity, not authority: `verified` is true because the signer proved control of its
 * credential to OAAth and is a member of the account, and a Grant still needs
 * its own owner approval.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type KernelAccountProfile,
  type OwnerCredentialProfile,
  parseKernelAccountProfile,
  parseOwnerCredentialProfile,
} from "@oaath/protocol";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { clientFail, OaathClientError } from "./errors.js";

/** The message a redirect page posts to its opener. */
const RESPONSE_MESSAGE = "oaath.authorization-response/v1";
const DEFAULT_TIMEOUT_MS = 5 * 60_000;
const POPUP_FEATURES = "popup,width=440,height=760";

export interface OaathLoginOptions {
  /** The OAAth issuer, for example `https://oaath.taek.tech` (no trailing slash). */
  readonly issuer: string;
  /** The client registered with the issuer (`POST /oauth/clients`). */
  readonly clientId: string;
  /** A registered redirect URI on this page's origin that runs `completeOAAthLogin`. */
  readonly redirectUri: string;
  /** How long the user may take in the popup. Defaults to five minutes. */
  readonly timeoutMs?: number;
}

/**
 * Opens the issuer's authorization page somewhere other than a popup, for
 * example `chrome.identity.launchWebAuthFlow` in an extension worker, and
 * resolves with the URL the issuer redirected to (`redirectUri` plus the
 * authorization response). Rejecting means the user did not finish.
 */
export type OaathAuthorizationLauncher = (authorizationUrl: string) => Promise<string>;

export interface OaathLoginSigner {
  readonly id: string;
  readonly kind: OwnerCredentialProfile["kind"];
  readonly profile: Readonly<OwnerCredentialProfile>;
}

/** One account the signer is an active member of (the id_token `oaath_accounts`). */
export interface OaathLoginAccount {
  /** The smart account's address, lowercase. */
  readonly address: `0x${string}`;
  /** `root` when the signer is the account's root; otherwise a permission member. */
  readonly role: "root" | "permission";
  readonly status: "active";
}

export interface OaathLogin {
  /** The chosen smart account's address (the id_token `sub`), lowercase. */
  readonly account: `0x${string}`;
  readonly accountProfile: Readonly<KernelAccountProfile>;
  /** The signer the user signed in with. */
  readonly signer: Readonly<OaathLoginSigner>;
  /** Every account the signer is an active member of, in the issuer's order. */
  readonly accounts: readonly Readonly<OaathLoginAccount>[];
  /** Always true: the signer proved control and is a member of the account. */
  readonly verified: true;
  /** The verified ES256 id_token, for the dapp's own backend. */
  readonly idToken: string;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function randomToken(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function captureOptions(value: OaathLoginOptions, launched = false) {
  const invalid = (message: string): never => clientFail("oaath_client_input_invalid", message);
  if (!value || typeof value !== "object") return invalid("login options are required");
  const { issuer, clientId, redirectUri, timeoutMs = DEFAULT_TIMEOUT_MS } = value;
  let issuerUrl: URL;
  let redirectUrl: URL;
  try {
    issuerUrl = new URL(issuer);
    redirectUrl = new URL(redirectUri);
  } catch {
    return invalid("issuer and redirectUri must be absolute URLs");
  }
  if (
    !["https:", "http:"].includes(issuerUrl.protocol) ||
    issuer !== `${issuerUrl.origin}${issuerUrl.pathname === "/" ? "" : issuerUrl.pathname}` ||
    issuer.endsWith("/")
  )
    return invalid("issuer must be an http(s) URL without a trailing slash");
  if (typeof clientId !== "string" || !/^[A-Za-z0-9._~-]{1,256}$/u.test(clientId))
    return invalid("clientId is invalid");
  // A launcher delivers the response itself; a popup posts it to this page.
  if (!launched && redirectUrl.origin !== location.origin)
    return invalid("redirectUri must be on this page's origin");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)
    return invalid("timeoutMs must be a positive integer");
  return { issuer, clientId, redirectUri, timeoutMs, redirectOrigin: redirectUrl.origin };
}

async function postForm(url: string, form: Record<string, string>): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      body: new URLSearchParams(form),
      credentials: "omit",
      cache: "no-store",
    });
  } catch (cause) {
    return clientFail("oaath_client_issuer_unavailable", "issuer is unreachable", null, null, {
      cause,
    });
  }
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    const error = typeof body?.error === "string" ? body.error : null;
    return clientFail("oaath_client_issuer_rejected", "issuer refused the request", error);
  }
  return body;
}

/** Waits for the redirect page's message from the popup, or its end. */
function authorizationResponse(
  popup: Window,
  redirectOrigin: string,
  timeoutMs: number,
): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    const finish = (settle: () => void) => {
      window.removeEventListener("message", onMessage);
      clearInterval(watch);
      clearTimeout(deadline);
      settle();
    };
    const onMessage = (event: MessageEvent) => {
      const data = event.data as { type?: unknown; url?: unknown } | null;
      if (
        event.origin !== redirectOrigin ||
        event.source !== popup ||
        data?.type !== RESPONSE_MESSAGE ||
        typeof data.url !== "string"
      )
        return;
      const url = new URL(data.url);
      finish(() => resolve(url.searchParams));
    };
    const watch = setInterval(() => {
      if (popup.closed)
        finish(() =>
          reject(
            new OaathClientError(
              "oaath_client_access_denied",
              "the sign-in window was closed",
              "popup_closed",
            ),
          ),
        );
    }, 500);
    const deadline = setTimeout(
      () =>
        finish(() =>
          reject(new OaathClientError("oaath_client_login_timeout", "sign-in timed out")),
        ),
      timeoutMs,
    );
    window.addEventListener("message", onMessage);
  });
}

/** What one popup authorization returned: the token response and the verified login. */
export interface OaathPopupAuthorization {
  readonly token: Readonly<Record<string, unknown>>;
  readonly login: Readonly<OaathLogin>;
}

/**
 * One authorization through the issuer's popup: PKCE, state, and nonce; PAR
 * with `extra` parameters (for example `authorization_details`); the popup;
 * the redirect page's response (state, RFC 9207 `iss`); the code exchange; and
 * the id_token verification. The caller opened `popup` inside the user's
 * gesture and closes it.
 */
export async function authorizeThroughPopup(
  popup: Window,
  value: OaathLoginOptions,
  extra: Readonly<Record<string, string>>,
): Promise<Readonly<OaathPopupAuthorization>> {
  const options = captureOptions(value);
  return authorize(options, extra, (url) => {
    popup.location.href = url;
    return authorizationResponse(popup, options.redirectOrigin, options.timeoutMs);
  });
}

/**
 * The same authorization through a caller-owned launcher instead of a popup.
 * The launcher's redirect must be `redirectUri` itself; everything after it is
 * checked exactly as a popup's response is.
 */
export async function authorizeWithLauncher(
  launch: OaathAuthorizationLauncher,
  value: OaathLoginOptions,
  extra: Readonly<Record<string, string>>,
): Promise<Readonly<OaathPopupAuthorization>> {
  const options = captureOptions(value, true);
  return authorize(options, extra, async (url) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new OaathClientError("oaath_client_login_timeout", "sign-in timed out")),
        options.timeoutMs,
      );
    });
    let redirect: string;
    try {
      redirect = await Promise.race([launch(url), expired]);
    } catch (cause) {
      if (cause instanceof OaathClientError) throw cause;
      return clientFail("oaath_client_access_denied", "the sign-in was not finished", null, null, {
        cause,
      });
    } finally {
      clearTimeout(timer);
    }
    let response: URL;
    try {
      response = new URL(redirect);
    } catch {
      return clientFail("oaath_client_issuer_rejected", "the launcher returned no redirect");
    }
    const expected = new URL(options.redirectUri);
    if (response.origin !== expected.origin || response.pathname !== expected.pathname)
      return clientFail("oaath_client_issuer_rejected", "the redirect is not the redirectUri");
    return response.searchParams;
  });
}

async function authorize(
  options: ReturnType<typeof captureOptions>,
  extra: Readonly<Record<string, string>>,
  open: (authorizationUrl: string) => Promise<URLSearchParams>,
): Promise<Readonly<OaathPopupAuthorization>> {
  const verifier = randomToken();
  const challenge = base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const state = randomToken();
  const nonce = randomToken();
  const pushed = (await postForm(`${options.issuer}/oauth/par`, {
    ...extra,
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "openid",
    state,
    nonce,
  })) as { request_uri?: unknown } | null;
  if (typeof pushed?.request_uri !== "string")
    return clientFail("oaath_client_issuer_rejected", "issuer returned no request_uri");
  const response = await open(
    `${options.issuer}/authorize?${new URLSearchParams({
      client_id: options.clientId,
      request_uri: pushed.request_uri,
    })}`,
  );
  if (response.get("state") !== state)
    return clientFail("oaath_client_state_mismatch", "authorization response state differs");
  // RFC 9207: the response must come from the issuer this authorization asked.
  if (response.get("iss") !== options.issuer)
    return clientFail("oaath_client_issuer_mismatch", "authorization response issuer differs");
  const error = response.get("error");
  if (error === "access_denied")
    return clientFail("oaath_client_access_denied", "the user cancelled", error);
  const code = response.get("code");
  if (error !== null || code === null)
    return clientFail("oaath_client_issuer_rejected", "authorization failed", error);

  const token = (await postForm(`${options.issuer}/oauth/token`, {
    grant_type: "authorization_code",
    client_id: options.clientId,
    code,
    code_verifier: verifier,
    redirect_uri: options.redirectUri,
  })) as Record<string, unknown> | null;
  if (typeof token?.id_token !== "string")
    return clientFail("oaath_client_issuer_rejected", "issuer returned no id_token");
  const login = await verifyIdToken(token.id_token, options.issuer, options.clientId, nonce);
  return Object.freeze({ token, login });
}

/** Opens the authorization popup; call it synchronously inside the user's gesture. */
export function openAuthorizationPopup(): Window {
  const popup = window.open("about:blank", "oaath-login", POPUP_FEATURES);
  if (!popup) return clientFail("oaath_client_popup_blocked", "the sign-in popup was blocked");
  return popup;
}

/**
 * Signs the user in with OAAth. Call it directly from a user gesture: the popup
 * opens before anything is awaited, so browsers do not block it.
 */
export async function loginWithOAAth(value: OaathLoginOptions): Promise<Readonly<OaathLogin>> {
  captureOptions(value);
  const popup = openAuthorizationPopup();
  try {
    return (await authorizeThroughPopup(popup, value, {})).login;
  } finally {
    popup.close();
  }
}

async function verifyIdToken(
  idToken: string,
  issuer: string,
  clientId: string,
  nonce: string,
): Promise<Readonly<OaathLogin>> {
  const invalid = (cause?: unknown): never =>
    clientFail("oaath_client_identity_invalid", "the id_token is invalid", null, null, { cause });
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(idToken, createRemoteJWKSet(new URL(`${issuer}/oauth/jwks`)), {
      issuer,
      audience: clientId,
      algorithms: ["ES256"],
    }));
  } catch (cause) {
    return invalid(cause);
  }
  if (payload.nonce !== nonce || payload.verified !== true) return invalid();
  const signer = payload.signer as { id?: unknown; profile?: unknown } | undefined;
  try {
    const accountProfile = parseKernelAccountProfile(payload.oaath_account);
    const profile = parseOwnerCredentialProfile(signer?.profile);
    if (
      typeof payload.sub !== "string" ||
      !/^0x[0-9a-f]{40}$/u.test(payload.sub) ||
      typeof signer?.id !== "string"
    )
      return invalid();
    const accounts = captureAccounts(payload.oaath_accounts);
    if (!accounts) return invalid();
    return Object.freeze({
      account: payload.sub as `0x${string}`,
      accountProfile,
      signer: Object.freeze({ id: signer.id, kind: profile.kind, profile }),
      accounts,
      verified: true,
      idToken,
    });
  } catch (cause) {
    if (cause instanceof OaathClientError) throw cause;
    return invalid(cause);
  }
}

/** The exact `oaath_accounts` claim, or null when any entry is malformed. */
function captureAccounts(value: unknown): readonly Readonly<OaathLoginAccount>[] | null {
  if (!Array.isArray(value)) return null;
  const accounts: Readonly<OaathLoginAccount>[] = [];
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return null;
    const { address, role, status, ...rest } = entry as Record<string, unknown>;
    if (
      Object.keys(rest).length > 0 ||
      typeof address !== "string" ||
      !/^0x[0-9a-f]{40}$/u.test(address) ||
      (role !== "root" && role !== "permission") ||
      status !== "active"
    )
      return null;
    accounts.push(Object.freeze({ address: address as `0x${string}`, role, status }));
  }
  return Object.freeze(accounts);
}

/**
 * Mount on the page at the registered redirect URI: hands the authorization
 * response to the window that started the login, on this origin only.
 */
export function completeOAAthLogin(): void {
  window.opener?.postMessage({ type: RESPONSE_MESSAGE, url: location.href }, location.origin);
}
