/**
 * The portal's view of the relay's same-origin `/portal/*` endpoints.
 *
 * Every wire shape the SPA reads or writes lives here, so the relay side
 * (stage 5a B1/B2) can adjust one module. The portal holds no authority:
 * nothing it sends is trusted as proof, and login carries no signature.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { KernelAccountProfile, OwnerCredentialProfile } from "@oaath/protocol";

/** RFC 6749 error body with the relay's structured code. */
export interface PortalErrorBody {
  readonly error: string;
  readonly error_description?: string;
  readonly error_code?: string;
}

/** `GET /portal/transactions/{par_id}`: one pending authorization. */
export interface PortalTransaction {
  readonly transaction_id: string;
  readonly client_id: string;
  readonly client_name: string;
  /** Origin of the registered redirect URI the dapp asked to return to. */
  readonly redirect_origin: string;
  /** Requested grant details; reviewed in a later screen, never here. */
  readonly authorization_details: readonly unknown[];
  /** Unix seconds after which the request is no longer usable. */
  readonly expires_at: number;
}

/** `POST /portal/signers`: register a public credential (idempotent). */
export interface RegisterSignerRequest {
  readonly profile: OwnerCredentialProfile;
}
export interface RegisterSignerResponse {
  readonly signer_id: string;
}

export type AccountRole = "root";

export interface PortalAccount {
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly role: AccountRole;
  readonly profile: KernelAccountProfile;
}

/** `GET /portal/signers/{id}/accounts`. */
export interface SignerAccountsResponse {
  readonly accounts: readonly PortalAccount[];
}

/** `POST /portal/accounts`: derive one counterfactual account offline. */
export interface CreateAccountRequest {
  readonly root_signer_id: string;
}
export interface CreateAccountResponse {
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly profile: KernelAccountProfile;
}

/** `POST /portal/transactions/{id}/decision`: the login outcome. */
export interface DecisionRequest {
  readonly signer_id: string;
  readonly account_id: string;
  readonly outcome: "approve" | "reject";
}
/** Also the shape of `GET /portal/transactions/{id}/redirect`. */
export interface RedirectResponse {
  readonly redirect: string;
}

/** A failed portal call with the relay's structured code, never its prose. */
export class PortalApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`portal request failed: ${code}`);
    this.name = "PortalApiError";
    this.status = status;
    this.code = code;
  }
}

const REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

/** The transaction id carried by a PAR `request_uri`, or null if malformed. */
export function transactionIdFromRequestUri(requestUri: string | null): string | null {
  if (!requestUri?.startsWith(REQUEST_URI_PREFIX)) return null;
  const id = requestUri.slice(REQUEST_URI_PREFIX.length);
  return /^[A-Za-z0-9._~-]{1,256}$/u.test(id) ? id : null;
}

async function call<Response>(path: string, init?: { method: "POST"; body: unknown }) {
  let response: globalThis.Response;
  try {
    response = await fetch(path, {
      method: init?.method ?? "GET",
      headers: init
        ? { accept: "application/json", "content-type": "application/json" }
        : { accept: "application/json" },
      body: init ? JSON.stringify(init.body) : null,
      credentials: "omit",
      cache: "no-store",
    });
  } catch {
    throw new PortalApiError(0, "network_unavailable");
  }
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const error = body as Partial<PortalErrorBody> | null;
    throw new PortalApiError(response.status, error?.error_code ?? error?.error ?? "unknown");
  }
  return body as Response;
}

const segment = encodeURIComponent;

export const portalApi = {
  transaction: (id: string) => call<PortalTransaction>(`/portal/transactions/${segment(id)}`),
  registerSigner: (body: RegisterSignerRequest) =>
    call<RegisterSignerResponse>("/portal/signers", { method: "POST", body }),
  signerAccounts: (signerId: string) =>
    call<SignerAccountsResponse>(`/portal/signers/${segment(signerId)}/accounts`),
  createAccount: (body: CreateAccountRequest) =>
    call<CreateAccountResponse>("/portal/accounts", { method: "POST", body }),
  decide: (id: string, body: DecisionRequest) =>
    call<RedirectResponse>(`/portal/transactions/${segment(id)}/decision`, {
      method: "POST",
      body,
    }),
  redirect: (id: string) => call<RedirectResponse>(`/portal/transactions/${segment(id)}/redirect`),
};
