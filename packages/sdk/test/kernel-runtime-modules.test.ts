import { readFile } from "node:fs/promises";
import { getCreate2Address, type Hex, keccak256, sliceHex } from "viem";
import { describe, expect, it } from "vitest";
import {
  type KernelReadRequest,
  type KernelRuntimeModule,
  kernelDeployment,
  kernelRuntimeReadiness,
  prepareRuntimeModuleDeployment,
} from "../src/kernel.js";

const CHAIN_ID = 143;
const MODULES: readonly KernelRuntimeModule[] = [
  "webauthn_signer",
  "rate_limit_policy",
  "validity_policy",
  "p256_verifier",
  "call_policy",
  "operation_limit_policy",
  "ecdsa_signer",
];

async function json(path: string): Promise<Record<string, any>> {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

/** The deployment input and runtime hash `oaath deploy-runtime` used before the SDK owned them. */
async function artifacts(): Promise<Record<KernelRuntimeModule, { input: Hex; hash: Hex }>> {
  const runtime = await json("../../contracts/artifacts/KernelV4Runtime.json");
  const validity = await json("../../contracts/artifacts/OaathKernelV4ValidityPolicy.json");
  const rateLimit = await json("./fixtures/kernel-rate-limit-deployment.json");
  return {
    call_policy: {
      input: runtime.callPolicy.deploymentInput,
      hash: runtime.callPolicy.runtimeCodeHash,
    },
    operation_limit_policy: {
      input: runtime.rateLimitPolicy.deploymentInput,
      hash: runtime.rateLimitPolicy.runtimeCodeHash,
    },
    ecdsa_signer: {
      input: runtime.ecdsaSigner.deploymentInput,
      hash: runtime.ecdsaSigner.runtimeCodeHash,
    },
    webauthn_signer: {
      input: runtime.webAuthnSigner.deploymentInput,
      hash: runtime.webAuthnSigner.runtimeCodeHash,
    },
    rate_limit_policy: { input: rateLimit.deploymentInput, hash: rateLimit.runtimeCodeHash },
    validity_policy: {
      input: validity.deployment.deploymentInput,
      hash: validity.deployment.runtimeCodeHash,
    },
    p256_verifier: {
      input: runtime.p256Verifier.deploymentInput,
      hash: runtime.p256Verifier.runtimeCodeHash,
    },
  };
}

const address = (module: KernelRuntimeModule) =>
  prepareRuntimeModuleDeployment({ chainId: CHAIN_ID, module }).address;

type Chain = Map<string, "pinned" | Hex | Error>;

/**
 * Owned fake with createKernelReads semantics: absent code hashes to undefined.
 * "pinned" stands for the module's exact runtime code, which only its hash names.
 */
async function statuses(chain: Chain) {
  const readiness = await kernelRuntimeReadiness({
    chainId: CHAIN_ID,
    reads: {
      read: async (request: KernelReadRequest): Promise<unknown> => {
        if (request.type === "chain_id") return CHAIN_ID;
        if (request.type !== "code" && request.type !== "runtime_code_hash")
          throw new Error("unexpected read");
        const value = chain.get(request.address) ?? "0x";
        if (value instanceof Error) throw value;
        if (value === "pinned") {
          if (request.type === "code") throw new Error("pinned code is never read");
          const module = MODULES.find((name) => address(name) === request.address);
          return prepareRuntimeModuleDeployment({
            chainId: CHAIN_ID,
            module: module as KernelRuntimeModule,
          }).expectedRuntimeCodeHash;
        }
        if (request.type === "code") return value;
        return value === "0x" ? undefined : keccak256(value);
      },
    },
  });
  return Object.fromEntries(readiness.modules.map((row) => [row.module, row.status]));
}

const allPinned = (): Chain => new Map(MODULES.map((module) => [address(module), "pinned"]));

describe("OAAth runtime module deployment", () => {
  it("prepares exactly the transaction oaath deploy-runtime sends for every module", async () => {
    const expected = await artifacts();
    const deployer = kernelDeployment({ chainId: CHAIN_ID }).create2Deployer;
    for (const module of MODULES) {
      const prepared = prepareRuntimeModuleDeployment({ chainId: CHAIN_ID, module });
      expect(prepared).toEqual({
        module,
        address: getCreate2Address({
          from: deployer,
          salt: sliceHex(expected[module].input, 0, 32),
          bytecode: sliceHex(expected[module].input, 32),
        }).toLowerCase(),
        to: deployer,
        data: expected[module].input,
        value: 0n,
        expectedRuntimeCodeHash: expected[module].hash,
      });
      expect(sliceHex(prepared.data, 0, 32)).toBe(`0x${"00".repeat(32)}`);
      expect(Object.isFrozen(prepared)).toBe(true);
    }
  });

  it("rejects an unknown module and an unsupported chain", () => {
    expect(() =>
      prepareRuntimeModuleDeployment({
        chainId: CHAIN_ID,
        module: "unknown" as KernelRuntimeModule,
      }),
    ).toThrow(expect.objectContaining({ code: "kernel_runtime_input_invalid" }));
    expect(() => prepareRuntimeModuleDeployment({ chainId: 0, module: "p256_verifier" })).toThrow(
      expect.objectContaining({ code: "kernel_runtime_chain_unsupported" }),
    );
  });
});

describe("OAAth runtime module readiness", () => {
  it.each(MODULES)("does not report all-present with missing %s", async (module) => {
    const chain = allPinned();
    chain.set(address(module), "0x");
    const result = await statuses(chain);
    expect(result[module]).toBe("missing");
    expect(Object.values(result).filter((status) => status === "present")).toHaveLength(
      MODULES.length - 1,
    );
  });
  it("reports every module present when each carries its pinned runtime hash", async () => {
    expect(await statuses(allPinned())).toEqual({
      webauthn_signer: "present",
      rate_limit_policy: "present",
      validity_policy: "present",
      p256_verifier: "present",
      call_policy: "present",
      operation_limit_policy: "present",
      ecdsa_signer: "present",
    });
  });

  it("reports empty code as missing, other code as mismatch and a failed read as unreadable", async () => {
    const chain = allPinned();
    chain.set(address("webauthn_signer"), "0x");
    chain.set(address("rate_limit_policy"), "0xdeadbeef");
    chain.set(address("validity_policy"), new Error("provider unavailable"));
    expect(await statuses(chain)).toEqual({
      webauthn_signer: "missing",
      rate_limit_policy: "mismatch",
      validity_policy: "unreadable",
      p256_verifier: "present",
      call_policy: "present",
      operation_limit_policy: "present",
      ecdsa_signer: "present",
    });
  });

  it("never reports absence from a contradictory or malformed read", async () => {
    const verifier = address("p256_verifier");
    const answer = (hash: unknown, code: unknown) =>
      kernelRuntimeReadiness({
        chainId: CHAIN_ID,
        reads: {
          read: async (request) => {
            if (request.type === "chain_id") return CHAIN_ID;
            if (!("address" in request) || request.address !== verifier) return undefined;
            return request.type === "code" ? code : hash;
          },
        },
      }).then((readiness) => readiness.modules.find((row) => row.address === verifier)?.status);
    expect(await answer(`0x${"11".repeat(32)}`, "0x")).toBe("unreadable");
    expect(await answer(undefined, "0xdeadbeef")).toBe("unreadable");
    expect(await answer(undefined, undefined)).toBe("unreadable");
    expect(await answer(undefined, "0xABCD")).toBe("unreadable");
  });

  it("reports every module unreadable when the reads are bound to another chain", async () => {
    const readiness = await kernelRuntimeReadiness({
      chainId: CHAIN_ID,
      reads: {
        read: async (request) => (request.type === "chain_id" ? 1 : "0x"),
      },
    });
    expect(readiness.modules.map((row) => row.status)).toEqual(MODULES.map(() => "unreadable"));
    expect(readiness.modules.every((row) => row.deployment === "oaath")).toBe(true);
  });
});
