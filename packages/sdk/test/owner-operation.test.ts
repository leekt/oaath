/**
 * Owner operations are prepared and verified offline. The relay's fixtures are
 * the SDK's own decisions: every case must reach the same stage here, and the
 * offline account derivation must match the Anvil-proven factory addresses.
 */
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { deriveKernelV33Account } from "../src/kernel/deployment/v33.js";
import { credentialKey } from "../src/kernel/key/credential.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { kernelV33PermissionRevocationCalls } from "../src/kernel/permission/v33-revocation.js";
import { prepareOwnerOperation, verifyOwnerOperation } from "../src/kernel.js";
import { deriveKernelV4RootAccountAddress, kernelV4Deployment } from "../src/kernel-v4.js";
import { portalRoot } from "./support/portal-roots.js";

async function relayFixture(path: string) {
  return JSON.parse(
    await readFile(new URL(`../../../relay/fixtures/${path}`, import.meta.url), "utf8"),
  );
}

const STAGES: Record<string, string> = {
  signing_request_invalid: "request",
  kernel_runtime_binding_mismatch: "binding",
  kernel_runtime_signature_invalid: "signature",
};

describe("owner operations", () => {
  it("reach the fixture's verification stage for every case", async () => {
    const fixtures = await relayFixture("kernel-approval/portal-root-owner-operations.json");
    for (const fixture of fixtures.cases) {
      const outcome = await verifyOwnerOperation(fixture.signed, fixtures.webauthn).then(
        () => ({ valid: true }),
        (error) => ({ valid: false, failure: STAGES[error.code] ?? error.code }),
      );
      expect(outcome, fixture.name).toEqual(fixture.expect);
    }
  });

  it("signs a Kernel 0.3.3 account's revocation on EntryPoint 0.7 and verifies it", async () => {
    const grants = await relayFixture("grant/kernelGrantApproval.json");
    const grant = grants.find(
      (entry: { name: string }) => entry.name === "kernel 0.3.3 ecdsa root, webauthn signer",
    );
    const approval = JSON.parse(grant.expect.ok.artifact).installApproval;
    // An enabled-nowhere permission: revocation consumes its own enable nonce.
    const calls = kernelV33PermissionRevocationCalls({
      approval,
      state: {
        currentNonce: approval.nonce,
        validationNonce: "0",
        hook: `0x${"00".repeat(20)}`,
        signer: `0x${"00".repeat(20)}`,
        permissionFlag: "0x0000",
        policies: [],
      },
    });
    expect(calls).toHaveLength(2);
    const root = portalRoot("ecdsa");
    const account = {
      version: "oaath.kernel-existing-account-profile/v1",
      kind: "kernel",
      kernelVersion: "0.3.3",
      address: approval.account,
      entryPoint: { version: "0.7" },
      ownerCredential: root.credential,
    } as const;
    const prepared = prepareOwnerOperation({
      account: account as never,
      chainId: 8453,
      deployed: true,
      calls,
      nonce: { lane: "7", sequence: "0" },
      gas: {
        callGasLimit: "400000",
        verificationGasLimit: "200000",
        preVerificationGas: "60000",
        maxFeePerGas: "2000000",
        maxPriorityFeePerGas: "1000000",
      },
    });
    expect(prepared.request.entryPoint).toBe("0x0000000071727de22e5e9d8baf0edac6f37da032");
    const verified = await verifyOwnerOperation(await prepared.sign(root.key));
    expect(verified.userOperation.sender).toBe(approval.account);
    // EntryPoint 0.7's RPC shape: factory fields absent, a raw root signature.
    expect(verified.userOperation).not.toHaveProperty("factory");
    // An existing account deploys nothing.
    expect(() =>
      prepareOwnerOperation({
        account: account as never,
        chainId: 8453,
        deployed: false,
        calls,
        nonce: { lane: "7", sequence: "0" },
        gas: {
          callGasLimit: "1",
          verificationGasLimit: "1",
          preVerificationGas: "1",
          maxFeePerGas: "1",
          maxPriorityFeePerGas: "1",
        },
      }),
    ).toThrow(expect.objectContaining({ code: "kernel_runtime_input_invalid" }));
  });

  it("deploys a counterfactual Kernel 0.3.3 account at its index, and only there", async () => {
    const root = portalRoot("ecdsa");
    const owner = (root.credential as { address: `0x${string}` }).address;
    const derived = deriveKernelV33Account({ owner, accountIndex: "3" });
    const account = {
      version: "oaath.kernel-existing-account-profile/v1",
      kind: "kernel",
      kernelVersion: "0.3.3",
      address: derived.address,
      entryPoint: { version: "0.7" },
      ownerCredential: root.credential,
    } as const;
    const input = {
      account: account as never,
      chainId: 8453,
      deployed: false,
      // The activation call: a self no-op.
      calls: [{ target: derived.address, value: "0", data: "0x" as const }],
      nonce: { lane: "0", sequence: "0" },
      gas: {
        callGasLimit: "100000",
        verificationGasLimit: "500000",
        preVerificationGas: "60000",
        maxFeePerGas: "2000000",
        maxPriorityFeePerGas: "1000000",
      },
    };
    const prepared = prepareOwnerOperation({ ...input, accountIndex: "3" });
    expect(prepared.request.userOperation.factory).toEqual({
      address: derived.factory,
      data: derived.factoryData,
    });
    const verified = await verifyOwnerOperation(await prepared.sign(root.key));
    expect(verified.userOperation).toMatchObject({
      sender: derived.address,
      factory: derived.factory,
      factoryData: derived.factoryData,
    });
    // Another index derives another address: refused before anything is signed.
    expect(() => prepareOwnerOperation({ ...input, accountIndex: "4" })).toThrow(
      expect.objectContaining({ code: "kernel_runtime_binding_mismatch" }),
    );
    // A deployed account takes no index.
    expect(() => prepareOwnerOperation({ ...input, deployed: true, accountIndex: "3" })).toThrow(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it("derives every factory-derived root account offline", async () => {
    const cases = await relayFixture("protocol/deriveKernelV4AccountAddress.json");
    const derivable = cases.filter((entry: { expect: object }) => "ok" in entry.expect);
    expect(derivable.length).toBeGreaterThan(10);
    for (const entry of derivable) {
      const key = credentialKey({
        credential: entry.input.account.ownerCredential,
        validator: entry.input.ownerValidator ?? null,
      });
      expect(
        deriveKernelV4RootAccountAddress({
          initialPackages: ownerOperator({ key }).resolvePackages(kernelV4Deployment(1)),
          accountIndex: entry.input.account.accountIndex,
        }),
        entry.name,
      ).toBe(entry.expect.ok);
    }
  });

  it("refuses a WebAuthn root's signature without its relying party", async () => {
    const root = portalRoot("webauthn");
    const signed = await prepareOwnerOperation({
      account: {
        version: "oaath.kernel-account-profile/v1",
        kind: "kernel",
        accountIndex: "0",
        kernelVersion: "0.4.0",
        factoryRoute: "kernel_factory",
        entryPoint: { version: "0.9" },
        ownerCredential: root.credential,
      },
      chainId: 8_453,
      deployed: true,
      calls: [{ target: `0x${"7a".repeat(20)}`, value: "1", data: "0x" }],
      nonce: { lane: "0", sequence: "3" },
      gas: {
        callGasLimit: "1",
        verificationGasLimit: "1",
        preVerificationGas: "1",
        maxFeePerGas: "1",
        maxPriorityFeePerGas: "1",
      },
    }).sign(root.key);
    expect(signed.request.userOperation.factory).toBeNull();
    await expect(verifyOwnerOperation(signed)).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
    });
  });
});
