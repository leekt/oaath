/**
 * Owner operations are prepared and verified offline. The relay's fixtures are
 * the SDK's own decisions: every case must reach the same stage here, and the
 * offline account derivation must match the Anvil-proven factory addresses.
 */
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { credentialKey } from "../src/kernel/key/credential.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
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
