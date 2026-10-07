/**
 * Owner operation approval through a simulated popup and portal: the PAR
 * carries the exact request, and only the root's verified signature over that
 * same request is returned.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { requestOwnerOperationApproval } from "../src/index.js";
import { prepareOwnerOperation } from "../src/kernel.js";
import { installOAuthPortal } from "./support/oauth-portal.js";
import { portalRoot } from "./support/portal-roots.js";

const root = portalRoot("ecdsa");
const other = portalRoot("ecdsa", "other");

function prepare(sequence: string) {
  return prepareOwnerOperation({
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
    deployed: false,
    calls: [{ target: `0x${"7a".repeat(20)}`, value: "1", data: "0x" }],
    nonce: { lane: "0", sequence },
    gas: {
      callGasLimit: "1",
      verificationGasLimit: "1",
      preVerificationGas: "1",
      maxFeePerGas: "1",
      maxPriorityFeePerGas: "1",
    },
  } as never);
}

async function approve(signOperation: (request: unknown) => Promise<unknown>) {
  const { approvals, pars } = await installOAuthPortal({ root, signOperation });
  const { kind: _, ...options } = approvals;
  return { options, pars };
}

afterEach(() => vi.unstubAllGlobals());

describe("requestOwnerOperationApproval", () => {
  it("returns the root's verified signature over exactly the requested operation", async () => {
    const prepared = prepare("3");
    const { options, pars } = await approve(() => prepared.sign(root.key));
    const verified = await requestOwnerOperationApproval({ ...options, request: prepared.request });
    expect(verified.signed.request).toEqual(prepared.request);
    expect(verified.userOperation.sender).toBe(prepared.request.userOperation.sender);
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail).toEqual({ type: "oaath_operation", request: prepared.request });
  });

  it("authorizes through a caller-owned launcher instead of a popup", async () => {
    const prepared = prepare("3");
    const { approvals, launch, window } = await installOAuthPortal({
      root,
      signOperation: () => prepared.sign(root.key),
    });
    const { kind: _, ...options } = approvals;
    const verified = await requestOwnerOperationApproval({
      ...options,
      request: prepared.request,
      launch,
    });
    expect(verified.signed.request).toEqual(prepared.request);
    expect(launch).toHaveBeenCalledTimes(1);
    expect(window.open).not.toHaveBeenCalled();
  });

  it("refuses a signed operation for another request", async () => {
    const prepared = prepare("3");
    const { options } = await approve(() => prepare("4").sign(root.key));
    await expect(
      requestOwnerOperationApproval({ ...options, request: prepared.request }),
    ).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "oauth_operation_mismatch",
    });
  });

  it("refuses a signature that is not the root's", async () => {
    const prepared = prepare("3");
    const { options } = await approve(async () => ({
      ...(await prepared.sign(root.key)),
      signature: await other.key.sign(prepared.request.userOperationHash),
    }));
    await expect(
      requestOwnerOperationApproval({ ...options, request: prepared.request }),
    ).rejects.toMatchObject({ code: "oaath_client_signing_failed" });
  });
});
