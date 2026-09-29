/**
 * The one public key constructor. Credential kind is an optional setting, and
 * the signing source is decided by which input is given: a local `account`, a
 * connected `wallet`, a P-256 `sign` capability, a WebAuthn `authenticate`
 * capability, or a public `credential` alone. Each kind's behavior stays owned by
 * its own `kernel/key/*` profile; this only dispatches to it.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OperatorCredentialProfile, OwnerCredentialProfile } from "@oaath/protocol";
import { captureInput, inputInvalid } from "../internal.js";
import type { KernelBuiltInKeyKind, KeyProfile } from "../types.js";
import { credentialKey } from "./credential.js";
import { type EcdsaKeyInput, type EcdsaWalletKeyInput, ecdsaKey, ecdsaWalletKey } from "./ecdsa.js";
import { type P256KeyInput, p256Key } from "./p256.js";
import { type WebAuthnKeyInput, webauthnKey } from "./webauthn.js";

/** A public credential with no signer: identity and package derivation only. */
export interface KernelPublicKeyInput {
  readonly credential: Readonly<OwnerCredentialProfile | OperatorCredentialProfile>;
  /** ECDSA root validator when root authority is composed; defaults to none. */
  readonly validator?: `0x${string}` | null;
}

export type KernelKeyInput =
  | (EcdsaKeyInput & { readonly kind?: "ecdsa" })
  | (EcdsaWalletKeyInput & { readonly kind?: "ecdsa" })
  | (P256KeyInput & { readonly kind?: "p256" })
  | (WebAuthnKeyInput & { readonly kind?: "webauthn" })
  | (KernelPublicKeyInput & { readonly kind?: KernelBuiltInKeyKind });

function withoutKind(record: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const { kind: _kind, ...rest } = record;
  return rest;
}

export function kernelKey(value: KernelKeyInput): Readonly<KeyProfile> {
  const record = captureInput(value, "Kernel key", new WeakSet());
  const kind = record.kind;
  if (kind !== undefined && kind !== "ecdsa" && kind !== "p256" && kind !== "webauthn") {
    return inputInvalid("Kernel key kind is unsupported");
  }
  const input = withoutKind(record);
  const key = Object.hasOwn(input, "account")
    ? ecdsaKey(input as unknown as EcdsaKeyInput)
    : Object.hasOwn(input, "wallet")
      ? ecdsaWalletKey(input as unknown as EcdsaWalletKeyInput)
      : Object.hasOwn(input, "authenticate")
        ? webauthnKey(input as unknown as WebAuthnKeyInput)
        : Object.hasOwn(input, "sign")
          ? p256Key(input as unknown as P256KeyInput)
          : credentialKey({ validator: null, ...input } as Parameters<typeof credentialKey>[0]);
  if (kind !== undefined && key.kind !== kind) {
    return inputInvalid("Kernel key kind does not match its input");
  }
  return key;
}
