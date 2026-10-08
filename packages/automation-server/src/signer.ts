/**
 * Session-key custody: one secp256k1 key per scope, sealed at rest with the
 * service's AES-256-GCM key. The scope is the application's user (default) or
 * the whole application; it is frozen into each plan at creation.
 *
 * ```text
 * state and owner      absent -> bound, by this module; there is no delete or rotate
 * persisted evidence   address, device id, sealed private key, keyed by scope
 * retry safe?          creation is insert-if-absent; a race exposes only the winner
 * forbidden            recovering a key whose address differs from the expected one
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */
import { randomBytes } from "node:crypto";
import {
  type EcdsaOperatorCredentialProfile,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
} from "@oaath/protocol";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { CustodyError, now, open, type Pool, seal } from "./db.js";

export type KeyScope = "user" | "application";

export interface SignerIdentity {
  readonly scopeId: string;
  readonly address: `0x${string}`;
  readonly deviceId: string;
}

export interface SessionSigner extends SignerIdentity {
  readonly credential: Readonly<EcdsaOperatorCredentialProfile>;
  /** The raw-hash signer `kernelKey({ account })` consumes. */
  readonly account: Readonly<{
    address: `0x${string}`;
    sign: (request: Readonly<{ hash: `0x${string}` }>) => Promise<`0x${string}`>;
  }>;
  /** EIP-191 signature, for issuer requests proven by the session key. */
  readonly signMessage: (message: string) => Promise<`0x${string}`>;
}

export function signerScope(
  plan: Readonly<{ app_id: string; user_id: string; key_scope: string }>,
) {
  return plan.key_scope === "application"
    ? `application:${plan.app_id}`
    : `user:${plan.app_id}:${plan.user_id}`;
}

export function operatorCredential(address: `0x${string}`): EcdsaOperatorCredentialProfile {
  return Object.freeze({
    version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
    kind: "ecdsa",
    address,
  }) as EcdsaOperatorCredentialProfile;
}

/** The scope's signer, created once. Concurrent creators all see the same winner. */
export async function ensureSigner(
  pool: Pool,
  sealKey: Buffer,
  scopeId: string,
): Promise<SignerIdentity> {
  const existing = await pool.query(
    "SELECT address, device_id FROM automation_signers WHERE scope_id=$1",
    [scopeId],
  );
  if (existing.rows[0] === undefined) {
    const privateKey = generatePrivateKey();
    const address = privateKeyToAccount(privateKey).address.toLowerCase();
    await pool.query(
      "INSERT INTO automation_signers(scope_id,address,device_id,sealed,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
      [
        scopeId,
        address,
        randomBytes(16).toString("hex"),
        seal(sealKey, { privateKey, address }, `signer:${scopeId}`),
        now(),
      ],
    );
  }
  const row = (
    await pool.query("SELECT address, device_id FROM automation_signers WHERE scope_id=$1", [
      scopeId,
    ])
  ).rows[0];
  if (row === undefined) throw new CustodyError();
  return Object.freeze({ scopeId, address: row.address, deviceId: row.device_id });
}

/** Opens the sealed key; it must still be the address the plan's Grant names. */
export async function loadSigner(
  pool: Pool,
  sealKey: Buffer,
  scopeId: string,
  expectedAddress: string,
): Promise<SessionSigner> {
  const row = (
    await pool.query(
      "SELECT address, device_id, sealed FROM automation_signers WHERE scope_id=$1",
      [scopeId],
    )
  ).rows[0];
  if (row === undefined) throw new CustodyError();
  const opened = open<{ privateKey: `0x${string}`; address: string }>(
    sealKey,
    row.sealed,
    `signer:${scopeId}`,
  );
  const account = privateKeyToAccount(opened.privateKey);
  const address = account.address.toLowerCase() as `0x${string}`;
  if (address !== row.address || address !== expectedAddress.toLowerCase())
    throw new CustodyError();
  return Object.freeze({
    scopeId,
    address,
    deviceId: row.device_id,
    credential: operatorCredential(address),
    account: Object.freeze({
      address,
      sign: async ({ hash }: Readonly<{ hash: `0x${string}` }>) =>
        (await account.sign({ hash })) as `0x${string}`,
    }),
    signMessage: async (message: string) =>
      (await account.signMessage({ message })) as `0x${string}`,
  });
}
