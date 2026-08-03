import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { bytesToHex, hexToBytes, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import {
  createKernelRuntime,
  diagnoseKernelCapability,
  ecdsaKey,
  type KernelCapability,
  type KernelCapabilityEvidence,
  type KernelCapabilityReason,
  type KernelKeyKind,
  type KernelRuntime,
  type KernelRuntimeErrorCode,
  type KernelV4SupportedChainId,
  type KeyProfile,
  kernelV4Deployment,
  type OperatorProfile,
  ownerOperator,
  p256Key,
  pinnedSignerModule,
  sessionOperator,
  webauthnKey,
} from "../src/index.js";

const chainIds: readonly KernelV4SupportedChainId[] = [46_630, 421_614, 11_155_111];
const validator = `0x${"22".repeat(20)}` as const;
const target = `0x${"44".repeat(20)}` as const;

const ecdsaAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const p256PublicKey = bytesToHex(p256.getPublicKey(hexToBytes(`0x${"23".repeat(32)}`), false));
const credentialId = "AAECAwQFBgcICQoLDA0ODw";

function base64UrlBytes(value: string): Uint8Array {
  const padded = value
    .replace(/-/gu, "+")
    .replace(/_/gu, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

const p256Credential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "p256" as const,
  publicKey: p256PublicKey,
});
const webauthnCredential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "webauthn" as const,
  publicKey: p256PublicKey,
  authenticatorIdHash: keccak256(bytesToHex(base64UrlBytes(credentialId))),
});

/** Diagnosis and composition never sign here, so the signing capabilities are unused. */
const keyProfiles: Readonly<Record<KernelKeyKind, () => Readonly<KeyProfile>>> = Object.freeze({
  ecdsa: () => ecdsaKey({ account: ecdsaAccount, validator }),
  p256: () => p256Key({ credential: p256Credential, sign: () => Promise.resolve("0x") }),
  webauthn: () =>
    webauthnKey({
      credential: webauthnCredential,
      credentialId,
      rpId: "app.example",
      origin: "https://app.example",
      authenticate: () => Promise.resolve("0x"),
    }),
});

const reads = Object.freeze({ read: () => Promise.resolve("0x") });
/** The bounded scope every session capability composes; policies are required. */
const scope = Object.freeze({
  kind: "call" as const,
  calls: Object.freeze([
    Object.freeze({ target, selectors: Object.freeze(["0xe9ae5c53" as const]) }),
  ]),
});

type Expectation =
  | Readonly<{ status: "available"; evidence: KernelCapabilityEvidence }>
  | Readonly<{ status: "unsupported"; reason: KernelCapabilityReason }>;

/**
 * The exact fact every capability carries on every supported chain: Kernel v4
 * pins no raw P-256 or WebAuthn validator module and no policy hook module, and
 * the ECDSA validator is caller-bound and code-proven when an account binds.
 */
const EXPECTED_FACTS: Readonly<Record<KernelCapability, Expectation>> = Object.freeze({
  owner_ecdsa: Object.freeze({ status: "available", evidence: "caller_bound_validator" }),
  owner_p256: Object.freeze({
    status: "unsupported",
    reason: "validator_module_deployment_unproven",
  }),
  owner_webauthn: Object.freeze({
    status: "unsupported",
    reason: "validator_module_deployment_unproven",
  }),
  // A session is a permission, so its axis is the pinned signer module: ECDSA and
  // WebAuthn have one, raw P-256 does not.
  session_ecdsa: Object.freeze({ status: "available", evidence: "pinned_reviewed_module" }),
  session_p256: Object.freeze({
    status: "unsupported",
    reason: "signer_module_deployment_unproven",
  }),
  session_webauthn: Object.freeze({ status: "available", evidence: "pinned_reviewed_module" }),
  // CallPolicy enforces the call and value axes; no reviewed module enforces a
  // validity window or a per-chain operation count.
  hook_call: Object.freeze({ status: "available", evidence: "pinned_reviewed_module" }),
  hook_value: Object.freeze({ status: "available", evidence: "pinned_reviewed_module" }),
  hook_expiry: Object.freeze({
    status: "unsupported",
    reason: "policy_module_deployment_unproven",
  }),
  hook_operation_limit: Object.freeze({
    status: "unsupported",
    reason: "policy_module_deployment_unproven",
  }),
});

/** Every diagnosable capability; EXPECTED_FACTS proves this list covers the union. */
const capabilities = [
  "owner_ecdsa",
  "owner_p256",
  "owner_webauthn",
  "session_ecdsa",
  "session_p256",
  "session_webauthn",
  "hook_call",
  "hook_value",
  "hook_expiry",
  "hook_operation_limit",
] as const satisfies readonly KernelCapability[];

/** The composition failure each diagnosis reason must produce in the factory. */
const RUNTIME_CODES: Readonly<Record<KernelCapabilityReason, KernelRuntimeErrorCode>> =
  Object.freeze({
    validator_module_deployment_unproven: "kernel_runtime_validator_unavailable",
    signer_module_deployment_unproven: "kernel_runtime_signer_unavailable",
    policy_module_deployment_unproven: "kernel_runtime_policy_unavailable",
  });

/**
 * The composition each capability stands for. Hook capabilities compose the
 * available ECDSA validator so the policy hook module is the only axis that can
 * fail; the switch is exhaustive, so a new capability must be composed here.
 */
function operatorFor(capability: KernelCapability): Readonly<OperatorProfile> {
  switch (capability) {
    case "owner_ecdsa":
      return ownerOperator({ key: keyProfiles.ecdsa() });
    case "owner_p256":
      return ownerOperator({ key: keyProfiles.p256() });
    case "owner_webauthn":
      return ownerOperator({ key: keyProfiles.webauthn() });
    case "session_ecdsa":
      return sessionOperator({ key: keyProfiles.ecdsa(), policies: [scope] });
    case "session_p256":
      return sessionOperator({ key: keyProfiles.p256(), policies: [scope] });
    case "session_webauthn":
      return sessionOperator({ key: keyProfiles.webauthn(), policies: [scope] });
    case "hook_call":
      return sessionOperator({ key: keyProfiles.ecdsa(), policies: [scope] });
    case "hook_value":
      return sessionOperator({
        key: keyProfiles.ecdsa(),
        policies: [scope, { kind: "value", maximumValue: "1000" }],
      });
    case "hook_expiry":
      return sessionOperator({
        key: keyProfiles.ecdsa(),
        policies: [scope, { kind: "expiry", validAfter: "0", validUntil: "1750000000" }],
      });
    case "hook_operation_limit":
      return sessionOperator({
        key: keyProfiles.ecdsa(),
        policies: [scope, { kind: "operation-limit", maximumOperations: "5" }],
      });
  }
}

function compose(chainId: KernelV4SupportedChainId, capability: KernelCapability) {
  return () =>
    createKernelRuntime({
      deployment: kernelV4Deployment(chainId),
      operator: operatorFor(capability),
      reads,
    });
}

describe("Kernel capability diagnosis", () => {
  it("diagnoses every capability the runtime can compose", () => {
    expect([...capabilities].sort()).toEqual(Object.keys(EXPECTED_FACTS).sort());
  });

  it.each(chainIds)("returns the exact frozen fact for every capability on chain %i", (chainId) => {
    for (const capability of capabilities) {
      const fact = diagnoseKernelCapability({ chainId, capability });
      expect(fact).toEqual({ capability, chainId, ...EXPECTED_FACTS[capability] });
      expect(Object.isFrozen(fact)).toBe(true);
    }
  });

  it.each(chainIds)("agrees with createKernelRuntime on chain %i", (chainId) => {
    for (const capability of capabilities) {
      const fact = diagnoseKernelCapability({ chainId, capability });
      if (fact.status === "available") {
        const runtime = compose(chainId, capability)();
        expect(runtime.deployment.chainId).toBe(chainId);
        expect(runtime.authority).toBe(capability.startsWith("owner_") ? "owner" : "session");
        expect(runtime.authorityModule).toMatch(/^0x[0-9a-f]{40}$/u);
        continue;
      }
      // The diagnosed reason chooses the expected code, so neither side can
      // drift into a hardcoded parallel table.
      expect(compose(chainId, capability)).toThrowError(
        expect.objectContaining({
          name: "OaathKernelRuntimeError",
          code: RUNTIME_CODES[fact.reason],
        }),
      );
    }
  });

  it.each(["p256", "webauthn"] as const)(
    "never downgrades a %s credential to ECDSA authority",
    (kind) => {
      const chainId = 421_614;
      const deployment = kernelV4Deployment(chainId);
      // The ECDSA authority is reachable on this chain, so an accidental
      // fallback would have produced a runtime instead of failing.
      expect(
        createKernelRuntime({
          deployment,
          operator: ownerOperator({ key: keyProfiles.ecdsa() }),
          reads,
        }).authorityModule,
      ).toBe(validator);

      const key = keyProfiles[kind]();
      expect(key.kind).toBe(kind);
      expect(key.publicMaterial).not.toBe(ecdsaAccount.address.toLowerCase());
      // Neither kind has a reviewed validator module, so root authority fails
      // closed for both.
      expect(() => key.resolveValidator(deployment)).toThrowError(
        expect.objectContaining({ code: "kernel_runtime_validator_unavailable" }),
      );
      let runtime: Readonly<KernelRuntime> | null = null;
      let code: unknown = null;
      try {
        runtime = createKernelRuntime({
          deployment,
          operator: ownerOperator({ key }),
          reads,
        });
      } catch (error) {
        code = (error as Readonly<{ code: unknown }>).code;
      }
      expect(runtime).toBeNull();
      expect(code).toBe("kernel_runtime_validator_unavailable");
      expect(diagnoseKernelCapability({ chainId, capability: `owner_${kind}` })).toEqual({
        capability: `owner_${kind}`,
        chainId,
        status: "unsupported",
        reason: "validator_module_deployment_unproven",
      });

      // A session resolves the signer axis instead. Raw P-256 has no reviewed
      // signer and fails closed on that axis; WebAuthn has one, and it must be
      // the WebAuthn module, never the ECDSA one.
      if (kind === "p256") {
        expect(() => sessionOperator({ key, policies: [scope] })).toThrowError(
          expect.objectContaining({ code: "kernel_runtime_signer_unavailable" }),
        );
        expect(diagnoseKernelCapability({ chainId, capability: "session_p256" })).toEqual({
          capability: "session_p256",
          chainId,
          status: "unsupported",
          reason: "signer_module_deployment_unproven",
        });
        return;
      }
      const session = createKernelRuntime({
        deployment,
        operator: sessionOperator({ key, policies: [scope] }),
        reads,
      });
      expect(session.keyKind).toBe("webauthn");
      expect(session.authorityModule).toBe(pinnedSignerModule("webauthn"));
      expect(session.authorityModule).not.toBe(pinnedSignerModule("ecdsa"));
      expect(session.packages[1]?.moduleData.endsWith(key.publicMaterial.slice(2))).toBe(true);
    },
  );

  it.each([
    ["an unknown credential capability", { chainId: 421_614, capability: "owner_bls" }],
    ["an undiagnosed hook axis", { chainId: 421_614, capability: "hook_gas" }],
    ["a prototype member", { chainId: 421_614, capability: "toString" }],
    ["a capability prefix only", { chainId: 421_614, capability: "owner" }],
    ["a non-string capability", { chainId: 421_614, capability: 1 }],
    ["a missing capability", { chainId: 421_614 }],
    ["an unknown field", { chainId: 421_614, capability: "owner_ecdsa", extra: 1 }],
    ["a non-record input", "owner_ecdsa"],
    ["a null input", null],
    ["an array input", [421_614, "owner_ecdsa"]],
  ] as const)("fails closed on %s", (_label, input) => {
    expect(() => diagnoseKernelCapability(input as never)).toThrowError(
      expect.objectContaining({
        name: "OaathKernelRuntimeError",
        code: "kernel_runtime_input_invalid",
      }),
    );
  });

  it("fails closed on an accessor-bearing input", () => {
    const input = {};
    Object.defineProperty(input, "chainId", { get: () => 421_614, enumerable: true });
    Object.defineProperty(input, "capability", { value: "owner_ecdsa", enumerable: true });
    expect(() => diagnoseKernelCapability(input as never)).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it.each([
    ["an unsupported chain", 1],
    ["a zero chain", 0],
    ["a decimal chain id", 421_614.5],
    ["a negative chain id", -421_614],
    ["a stringified chain id", "421614"],
    ["a hex chain id", "0x66eee"],
    ["a bigint chain id", 421_614n],
    ["a non-finite chain id", Number.NaN],
  ] as const)("rejects %s", (_label, chainId) => {
    expect(() =>
      diagnoseKernelCapability({ chainId, capability: "owner_ecdsa" } as never),
    ).toThrowError(
      expect.objectContaining({
        name: "OaathKernelV4Error",
        code: "kernel_v4_chain_unsupported",
      }),
    );
  });
});
