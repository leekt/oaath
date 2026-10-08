/**
 * Who may call the API: an application by its credential, or one of its users
 * by a one-hour session the application's backend issued for exactly one
 * user and account. Only token hashes are stored.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { KeyScope } from "@oaath/automation";
import { type ServiceContext, ServiceError } from "./context.js";

export const SESSION_SECONDS = 3600;

export interface Principal {
  readonly appId: string;
  /** Present for user sessions; an application credential acts for no user. */
  readonly user: Readonly<{ userId: string; account: `0x${string}` }> | null;
}

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

function bearer(headers: IncomingHttpHeaders): string {
  const value = headers.authorization;
  const token =
    typeof value === "string" ? value.match(/^Bearer ([\x21-\x7e]{16,512})$/u)?.[1] : null;
  if (!token) throw new ServiceError("authentication_required", 401);
  return token;
}

function application(context: ServiceContext, digest: string): string | null {
  const supplied = Buffer.from(digest, "hex");
  for (const app of context.config.applications) {
    if (timingSafeEqual(supplied, Buffer.from(app.tokenSha256, "hex"))) return app.id;
  }
  return null;
}

export function requireApplication(context: ServiceContext, headers: IncomingHttpHeaders): string {
  const appId = application(context, sha256(bearer(headers)));
  if (appId === null) throw new ServiceError("application_credential_required", 401);
  return appId;
}

export async function authenticate(
  context: ServiceContext,
  headers: IncomingHttpHeaders,
): Promise<Principal> {
  const digest = sha256(bearer(headers));
  const appId = application(context, digest);
  if (appId !== null) return { appId, user: null };
  const row = (
    await context.pool.query(
      "SELECT app_id, user_id, account FROM automation_sessions WHERE token_hash=$1 AND expires_at>$2",
      [digest, context.now()],
    )
  ).rows[0];
  if (row === undefined) throw new ServiceError("session_expired_or_invalid", 401);
  // Removing an application credential also closes its sessions.
  if (!context.config.applications.some((app) => app.id === row.app_id))
    throw new ServiceError("application_unavailable", 401);
  return { appId: row.app_id, user: { userId: row.user_id, account: row.account } };
}

export async function keyScope(context: ServiceContext, appId: string): Promise<KeyScope> {
  const row = (
    await context.pool.query("SELECT key_scope FROM automation_applications WHERE app_id=$1", [
      appId,
    ])
  ).rows[0];
  return row?.key_scope ?? "user";
}

export async function configureApplication(
  context: ServiceContext,
  appId: string,
  body: Record<string, unknown>,
): Promise<{ keyScope: KeyScope }> {
  const scope = body.keyScope;
  if (Object.keys(body).length !== 1 || (scope !== "user" && scope !== "application"))
    throw new ServiceError("key_scope_invalid", 422);
  await context.pool.query(
    "INSERT INTO automation_applications(app_id,key_scope) VALUES($1,$2) ON CONFLICT (app_id) DO UPDATE SET key_scope=EXCLUDED.key_scope",
    [appId, scope],
  );
  return { keyScope: scope };
}

/** Only the application's authenticated backend can assert a user and account. */
export async function createSession(
  context: ServiceContext,
  appId: string,
  body: Record<string, unknown>,
) {
  const { userId, account } = body;
  if (
    Object.keys(body).length !== 2 ||
    typeof userId !== "string" ||
    userId.length < 1 ||
    userId.length > 256 ||
    userId.trim() !== userId
  )
    throw new ServiceError("user_id_invalid", 422);
  if (
    typeof account !== "string" ||
    !/^0x[0-9a-fA-F]{40}$/u.test(account) ||
    /^0x0{40}$/u.test(account)
  )
    throw new ServiceError("account_invalid", 422);
  const token = randomBytes(32).toString("hex");
  const expiresAt = context.now() + SESSION_SECONDS;
  await context.pool.query(
    "INSERT INTO automation_sessions(token_hash,app_id,user_id,account,expires_at) VALUES($1,$2,$3,$4,$5)",
    [sha256(token), appId, userId, account.toLowerCase(), expiresAt],
  );
  await context.pool.query("DELETE FROM automation_sessions WHERE expires_at<=$1", [context.now()]);
  return {
    token,
    expiresAt,
    account: account.toLowerCase(),
    keyScope: await keyScope(context, appId),
  };
}
