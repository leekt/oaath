/**
 * The portal's view of the relay's same-origin `/portal/*` endpoints.
 *
 * Every wire shape the SPA reads or writes lives here, so the relay side
 * (stage 5a B1/B2) can adjust one module. A signer's accounts, account
 * creation, grant decisions, links and members need that signer's session: an
 * HttpOnly cookie the relay sets after the signer proves control
 * (`session.ts`).
 *
 * @author taek <leekt216@gmail.com>
 */
import type {
  Eip712OwnerSigningRequest,
  GrantPolicy,
  KernelAccountProfile,
  OperatorCredentialProfile,
  OwnerCredentialProfile,
  OwnerOperationRequest,
  PermissionRequest,
} from "@oaath/protocol";

/** RFC 6749 error body with the relay's structured code. */
export interface PortalErrorBody {
  /** `/portal/*` answers the relay envelope `{error: {code}}`. */
  readonly error: string | { readonly code?: string };
  readonly error_description?: string;
  readonly error_code?: string;
}

/** The dapp's requested grant: its own signer and the policy it may use. */
export interface GrantDetail {
  readonly type: "oaath_grant";
  readonly signer: OperatorCredentialProfile;
  readonly policy: GrantPolicy;
  /** The chains the dapp names; display-only, the approval covers every chain. */
  readonly chains: readonly number[];
  /** Unix seconds: the Grant's exclusive expiry. */
  readonly expires_at: number;
  readonly device_id: string;
}

/** One exact owner operation the dapp asks the account's root to sign. */
export interface OperationDetail {
  readonly type: "oaath_operation";
  readonly request: OwnerOperationRequest;
}

/** `GET /portal/transactions/{par_id}`: one pending authorization. */
export interface PortalTransaction {
  readonly transaction_id: string;
  readonly client_id: string;
  readonly client_name: string;
  /** Origin of the registered redirect URI the dapp asked to return to. */
  readonly redirect_origin: string;
  /** Empty for a login; one `oaath_grant` or `oaath_operation` detail otherwise. */
  readonly authorization_details: readonly (GrantDetail | OperationDetail)[];
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

/** `GET /portal/signers/by-credential/{credentialId}`: identification only. */
export interface IdentifiedSigner {
  readonly signer_id: string;
  readonly kind: OwnerCredentialProfile["kind"];
  readonly profile: OwnerCredentialProfile;
}

/** `POST /portal/sessions/challenge`: a single-use nonce, five minutes. */
export interface ChallengeRequest {
  /** Names a wallet signer, so the relay returns its Sign-In with Ethereum message. */
  readonly signer_id?: string;
}
export interface ChallengeResponse {
  /** 32 bytes as 64 hex digits; a passkey's WebAuthn challenge. */
  readonly nonce: string;
  readonly expires_at: number;
  /** The ERC-4361 message a wallet signer signs with `personal_sign`. */
  readonly message?: string;
}

/** `POST /portal/sessions`: sets the session cookie for this signer. */
export interface SignInRequest {
  readonly signer_id: string;
  readonly nonce: string;
  /** Wallet: the `personal_sign` signature; passkey: the WebAuthn assertion envelope. */
  readonly signature: string;
}
export interface SignInResponse {
  readonly signer_id: string;
  readonly expires_at: number;
}

/** `root`: the signer owns the account; `permission`: a scoped signer on it. */
export type AccountRole = "root" | "permission";

/** A suspended membership cannot sign in as the account. */
export type MembershipStatus = "active" | "suspended";

export interface PortalAccount {
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly role: AccountRole;
  readonly status: MembershipStatus;
  readonly profile: KernelAccountProfile;
}

/** `GET /portal/signers/{id}/accounts`. */
export interface SignerAccountsResponse {
  readonly accounts: readonly PortalAccount[];
}

/** `POST /portal/accounts`: derive one counterfactual account offline. */
export interface CreateAccountRequest {
  readonly root_signer_id: string;
  /**
   * The idempotency key of this one creation: a retry with the same key
   * answers the account it created, never a second one.
   */
  readonly creation_key: string;
}
export interface CreateAccountResponse {
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly profile: KernelAccountProfile;
}

/** `POST /portal/transactions/{id}/prepare`: only the account's root may prepare. */
export interface PrepareGrantRequest {
  readonly signer_id: string;
  readonly account_id: string;
}
export interface PrepareGrantResponse {
  /** The composed request the decision must approve, byte for byte. */
  readonly permission_request: PermissionRequest;
  readonly request_hash: `0x${string}`;
  readonly approved_policy: GrantPolicy;
  /** The Kernel replayable-install request the account root signs. */
  readonly signing_request: Eip712OwnerSigningRequest;
}

/** `POST /portal/transactions/{id}/decision`: the login or grant outcome. */
export type DecisionRequest =
  | {
      readonly outcome: "approved";
      readonly signer_id: string;
      readonly account_id: string;
      /** For a grant: the root-signed decision, `JSON.stringify(KernelPermissionDecision)`. */
      readonly artifact?: string;
    }
  /**
   * A grant asked for by a non-root member: the dapp gets its code at once and
   * its token after the account's root approves (`/requests/{id}`).
   */
  | {
      readonly outcome: "request_approval";
      readonly signer_id: string;
      readonly account_id: string;
    }
  /** The redirect then carries `error=access_denied`. */
  | { readonly outcome: "cancelled" };
/** Also the shape of `GET /portal/transactions/{id}/redirect`. */
export interface RedirectResponse {
  readonly redirect: string;
}

/** `POST /portal/links`: the signed-in new signer asks to join an account. */
export interface CreateLinkRequest {
  readonly signer_id: string;
  readonly account: `0x${string}`;
  /** The requester's name for this signer, shown to the account's owner. */
  readonly label: string;
}
export interface CreateLinkResponse {
  readonly link_id: string;
  readonly expires_at: number;
}

export type LinkStatus = "pending" | "approved" | "rejected" | "expired" | "removed";

/** The OAAth membership approval an account's root signs (EIP-712). */
export interface MembershipApprovalTypedData {
  readonly types: Readonly<Record<string, readonly { name: string; type: string }[]>>;
  readonly primaryType: "MembershipApproval";
  readonly domain: { readonly name: "OAAth"; readonly version: "1" };
  readonly message: {
    readonly account: `0x${string}`;
    readonly signerProfileHash: `0x${string}`;
    readonly role: "permission";
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly nonce: string;
  };
}

/** `GET /portal/links/{id}`: for the requester and the account's root. */
export interface PortalLink {
  readonly link_id: string;
  readonly status: LinkStatus;
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly signer: {
    readonly signer_id: string;
    readonly kind: OwnerCredentialProfile["kind"];
    readonly profile: OwnerCredentialProfile;
    readonly profile_hash: `0x${string}`;
  };
  readonly label: string;
  readonly role: "permission";
  readonly expires_at: number;
  readonly typed_data: MembershipApprovalTypedData;
  readonly digest: `0x${string}`;
  /** Set when the root approved with a policy template. */
  readonly grant_id: string | null;
}

/** `GET /portal/accounts/{id}/members`: the root's view of its account. */
export interface PortalMember {
  readonly signer_id: string;
  readonly kind: OwnerCredentialProfile["kind"];
  readonly profile: OwnerCredentialProfile;
  readonly role: AccountRole;
  /** A login-only member's link and label. */
  readonly link_id: string | null;
  readonly label: string | null;
  /** A dapp signer's grant. */
  readonly grant_id: string | null;
  readonly joined_at: number;
  readonly status: MembershipStatus;
  /** Unix seconds of the latest suspension. */
  readonly suspended_at: number | null;
}
export interface MembersResponse {
  readonly members: readonly PortalMember[];
}

/** A template's policy: a GrantPolicy without its validity window. */
export interface TemplatePolicy {
  readonly calls: readonly {
    readonly target: `0x${string}`;
    readonly selector: `0x${string}`;
    /** Decimal wei. */
    readonly valueLimit: string;
  }[];
  readonly perChainOperationLimit: {
    readonly count: number;
    readonly intervalSeconds: number | null;
  };
}

/** `/portal/accounts/{id}/policies`: the root's templates. */
export interface PolicyTemplate {
  readonly template_id: string;
  readonly name: string;
  readonly policy: TemplatePolicy;
  readonly lifetime_seconds: number;
  readonly created_at: number;
  readonly updated_at: number;
}
export interface PolicyTemplateInput {
  readonly name: string;
  readonly policy: TemplatePolicy;
  readonly lifetime_seconds: number;
}

/** `GET /portal/grants/{id}`: a member grant, for its root or member. */
export interface MemberGrantView {
  readonly grant_id: string;
  readonly status: "approved" | "rejected" | "invalidated";
  readonly permission_request: PermissionRequest;
  readonly decision: unknown;
  readonly enable: unknown;
}

/** `/portal/requests/{id}`: a member's grant request awaiting the account's root. */
export interface PendingRequest {
  readonly request_id: string;
  readonly status: "pending" | "approved" | "rejected" | "expired";
  readonly account_id: string;
  readonly address: `0x${string}`;
  readonly client_name: string;
  readonly redirect_origin: string;
  readonly member: {
    readonly signer_id: string;
    readonly kind: OwnerCredentialProfile["kind"];
    readonly profile: OwnerCredentialProfile;
  };
  /** The composed request the root approves: the dapp's signer and policy. */
  readonly permission_request: PermissionRequest;
  /** Display-only; the approval covers every chain. */
  readonly chains: readonly number[];
  readonly created_at: number;
  readonly expires_at: number;
}

/** `/portal/grants/{id}/revocation`: an invalidated grant's on-chain removal. */
export interface RevocationView {
  readonly grant_id: string;
  readonly status:
    | "not_installed"
    | "pending_signature"
    | "submitted"
    | "delivered"
    | "included"
    | "finalized"
    | "failed";
  readonly delivery: "relay" | "dapp";
  /** Uninstall an installed permission, or invalidate an unused enable; null when nothing is needed. */
  readonly action: "uninstall" | "invalidate" | null;
  /** The grant's enable install nonce, which an invalidation consumes. */
  readonly install_nonce: string;
  /** Whether OAAth submits the signed uninstall: always for relay delivery, by choice for dapp. */
  readonly relay_submits: boolean;
  /** The grant's install packages: what the uninstall removes. */
  readonly packages: unknown;
  /** The unsigned uninstall the root signs, while one is prepared. */
  readonly request: unknown;
  readonly user_operation_hash: string | null;
  readonly transaction_hash: string | null;
}

/** `POST /portal/accounts/import`: the root's signed import statement. */
export interface ImportAccountRequest {
  readonly root_signer_id: string;
  readonly address: `0x${string}`;
  /** The inventory fingerprint the root acknowledged. */
  readonly inventory_fingerprint: `0x${string}`;
  /** Unix seconds, as signed. */
  readonly issued_at: number;
  readonly nonce: string;
  readonly signature: `0x${string}`;
}

/** OAuth app metadata managed by its authenticated creating signer. */
export interface OAuthClientInput {
  readonly client_name: string;
  readonly redirect_uris: readonly string[];
  readonly token_endpoint_auth_method: "none";
  readonly revocation_delivery: "relay" | "dapp";
}
export interface OAuthClient extends OAuthClientInput {
  readonly client_id: string;
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

async function call<Response>(
  path: string,
  init?: { method: "POST" | "PUT"; body: unknown } | { method: "DELETE" },
) {
  const sent = init && "body" in init ? JSON.stringify(init.body) : null;
  let response: globalThis.Response;
  try {
    response = await fetch(path, {
      method: init?.method ?? "GET",
      headers: sent
        ? { accept: "application/json", "content-type": "application/json" }
        : { accept: "application/json" },
      body: sent,
      // The session cookie is same-origin and HttpOnly.
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new PortalApiError(0, "network_unavailable");
  }
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const error = body as Partial<PortalErrorBody> | null;
    const code =
      typeof error?.error === "object" ? error.error.code : (error?.error_code ?? error?.error);
    throw new PortalApiError(response.status, code ?? "unknown");
  }
  return body as Response;
}

const segment = encodeURIComponent;

export const portalApi = {
  clients: () => call<{ readonly clients: readonly OAuthClient[] }>("/portal/clients"),
  createClient: (body: OAuthClientInput) =>
    call<OAuthClient>("/portal/clients", { method: "POST", body }),
  updateClient: (id: string, body: OAuthClientInput) =>
    call<OAuthClient>(`/portal/clients/${segment(id)}`, { method: "PUT", body }),
  transaction: (id: string) => call<PortalTransaction>(`/portal/transactions/${segment(id)}`),
  challenge: (body: ChallengeRequest) =>
    call<ChallengeResponse>("/portal/sessions/challenge", { method: "POST", body }),
  signIn: (body: SignInRequest) =>
    call<SignInResponse>("/portal/sessions", { method: "POST", body }),
  signOut: () => call<Record<string, never>>("/portal/sessions", { method: "DELETE" }),
  registerSigner: (body: RegisterSignerRequest) =>
    call<RegisterSignerResponse>("/portal/signers", { method: "POST", body }),
  signerByCredential: (credentialId: string) =>
    call<IdentifiedSigner>(`/portal/signers/by-credential/${segment(credentialId)}`),
  signerAccounts: (signerId: string) =>
    call<SignerAccountsResponse>(`/portal/signers/${segment(signerId)}/accounts`),
  importAccount: (body: ImportAccountRequest) =>
    call<CreateAccountResponse>("/portal/accounts/import", { method: "POST", body }),
  createAccount: (body: CreateAccountRequest) =>
    call<CreateAccountResponse>("/portal/accounts", { method: "POST", body }),
  prepareGrant: (id: string, body: PrepareGrantRequest) =>
    call<PrepareGrantResponse>(`/portal/transactions/${segment(id)}/prepare`, {
      method: "POST",
      body,
    }),
  decide: (id: string, body: DecisionRequest) =>
    call<RedirectResponse>(`/portal/transactions/${segment(id)}/decision`, {
      method: "POST",
      body,
    }),
  redirect: (id: string) => call<RedirectResponse>(`/portal/transactions/${segment(id)}/redirect`),
  createLink: (body: CreateLinkRequest) =>
    call<CreateLinkResponse>("/portal/links", { method: "POST", body }),
  link: (id: string) => call<PortalLink>(`/portal/links/${segment(id)}`),
  approveLink: (id: string, signature: `0x${string}`) =>
    call<PortalLink>(`/portal/links/${segment(id)}/approve`, {
      method: "POST",
      body: { signature },
    }),
  /** Approval with a template: the root's signature is the member's enable. */
  approveLinkWithTemplate: (id: string, templateId: string, artifact: string) =>
    call<PortalLink>(`/portal/links/${segment(id)}/approve`, {
      method: "POST",
      body: { template_id: templateId, artifact },
    }),
  prepareLinkGrant: (id: string, templateId: string) =>
    call<PrepareGrantResponse>(`/portal/links/${segment(id)}/prepare`, {
      method: "POST",
      body: { template_id: templateId },
    }),
  policies: (accountId: string) =>
    call<{ readonly policies: readonly PolicyTemplate[] }>(
      `/portal/accounts/${segment(accountId)}/policies`,
    ),
  createPolicy: (accountId: string, body: PolicyTemplateInput) =>
    call<PolicyTemplate>(`/portal/accounts/${segment(accountId)}/policies`, {
      method: "POST",
      body,
    }),
  updatePolicy: (accountId: string, templateId: string, body: PolicyTemplateInput) =>
    call<PolicyTemplate>(`/portal/accounts/${segment(accountId)}/policies/${segment(templateId)}`, {
      method: "PUT",
      body,
    }),
  deletePolicy: (accountId: string, templateId: string) =>
    call<Record<string, never>>(
      `/portal/accounts/${segment(accountId)}/policies/${segment(templateId)}`,
      { method: "DELETE" },
    ),
  prepareAssignment: (accountId: string, signerId: string, templateId: string) =>
    call<PrepareGrantResponse>(
      `/portal/accounts/${segment(accountId)}/members/${segment(signerId)}/grants/prepare`,
      { method: "POST", body: { template_id: templateId } },
    ),
  assignGrant: (
    accountId: string,
    signerId: string,
    body: {
      readonly template_id: string;
      readonly request_id: string;
      readonly requested_at: number;
      readonly artifact: string;
    },
  ) =>
    call<{ readonly grant_id: string }>(
      `/portal/accounts/${segment(accountId)}/members/${segment(signerId)}/grants`,
      { method: "POST", body },
    ),
  pendingRequests: (accountId: string) =>
    call<{ readonly requests: readonly PendingRequest[] }>(
      `/portal/accounts/${segment(accountId)}/requests`,
    ),
  pendingRequest: (id: string) => call<PendingRequest>(`/portal/requests/${segment(id)}`),
  preparePending: (id: string) =>
    call<PrepareGrantResponse>(`/portal/requests/${segment(id)}/prepare`, {
      method: "POST",
      body: {},
    }),
  approvePending: (id: string, artifact: string) =>
    call<PendingRequest>(`/portal/requests/${segment(id)}/approve`, {
      method: "POST",
      body: { artifact },
    }),
  rejectPending: (id: string) =>
    call<PendingRequest>(`/portal/requests/${segment(id)}/reject`, { method: "POST", body: {} }),
  revocation: (grantId: string) =>
    call<RevocationView>(`/portal/grants/${segment(grantId)}/revocation`),
  prepareRevocation: (grantId: string, estimationSignature: string) =>
    call<RevocationView>(`/portal/grants/${segment(grantId)}/revocation/prepare`, {
      method: "POST",
      body: { estimation_signature: estimationSignature },
    }),
  /** `submitFromOaath` makes OAAth submit a revocation the dapp would otherwise submit. */
  signRevocation: (grantId: string, signature: string, submitFromOaath: boolean) =>
    call<RevocationView>(`/portal/grants/${segment(grantId)}/revocation/sign`, {
      method: "POST",
      body: { signature, submit_from_oaath: submitFromOaath },
    }),
  memberGrant: (grantId: string) => call<MemberGrantView>(`/portal/grants/${segment(grantId)}`),
  rejectLink: (id: string) =>
    call<PortalLink>(`/portal/links/${segment(id)}/reject`, { method: "POST", body: {} }),
  members: (accountId: string) =>
    call<MembersResponse>(`/portal/accounts/${segment(accountId)}/members`),
  /** Suspending also invalidates the member's grants; restoring revives none. */
  setMemberStatus: (accountId: string, signerId: string, action: "suspend" | "restore") =>
    call<{ readonly signer_id: string; readonly status: MembershipStatus }>(
      `/portal/accounts/${segment(accountId)}/members/${segment(signerId)}/${action}`,
      { method: "POST", body: {} },
    ),
  removeMember: (accountId: string, signerId: string) =>
    call<{ readonly removed: number }>(
      `/portal/accounts/${segment(accountId)}/members/${segment(signerId)}`,
      { method: "DELETE" },
    ),
};
