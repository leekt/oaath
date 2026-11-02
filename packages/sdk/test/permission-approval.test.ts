/**
 * A root-approved permission for a caller-held session credential through a
 * simulated popup and portal: the PAR names exactly the caller's signer and
 * policy, and only an approval installing exactly that signer, signed by the
 * account's root, is returned. A Kernel 0.3.3 account approves through the
 * SDK's own existing-account preparation.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { requestPermissionApproval } from "../src/index.js";
import { KERNEL_ENTRY_POINT_V07 } from "../src/kernel/deployment/v33.js";
import * as M from "../src/kernel/modules.js";
import {
  kernelGrantCapabilityHash,
  verifyKernelPermissionApproval,
} from "../src/kernel/permission/approval.js";
import { prepareKernelPermissionApproval } from "../src/kernel/permission/prepare-approval.js";
import { installOAuthPortal } from "./support/oauth-portal.js";
import { portalRoot } from "./support/portal-roots.js";

const root = portalRoot("ecdsa");
const other = portalRoot("ecdsa", "other");
const passkey = portalRoot("webauthn", "operator");
const SIGNER = { ...passkey.credential, version: "oaath.operator-credential-profile/v1" } as never;
const ACCOUNT = "0xc3a56de6dfc1dcef5113927ec09513918e8c44aa";
const V33_ACCOUNT = {
  version: "oaath.kernel-existing-account-profile/v1",
  kind: "kernel",
  kernelVersion: "0.3.3",
  address: ACCOUNT,
  entryPoint: { version: "0.7" },
  ownerCredential: root.credential,
};
const EXPIRES_AT = Math.floor(Date.now() / 1000) + 600;
const POLICY = {
  version: "oaath.grant-policy/v1",
  calls: [
    { target: `0x${"aa".repeat(20)}`, selector: "0xa9059cbb", valueLimit: "0", argumentEquals: [] },
  ],
  validAfter: 0,
  validUntil: EXPIRES_AT - 1,
  perChainOperationLimit: { count: 5, intervalSeconds: 86_400 },
} as never;

/** Arbitrum Sepolia showing a Kernel 0.3.3 account rooted in `root`, at enable nonce 1. */
const RUNTIME_CODE_HASHES = new Map<string, string>([
  [KERNEL_ENTRY_POINT_V07.address, KERNEL_ENTRY_POINT_V07.runtimeCodeHash],
  [M.OAATH_KERNEL_V4_VALIDITY_POLICY, M.OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH],
  [M.OAATH_KERNEL_RATE_LIMIT_POLICY, M.OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH],
  [M.KERNEL_P256_VERIFIER, M.KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH],
]);
const answers: Record<string, (request: { address?: string }) => unknown> = {
  chain_id: () => 421_614,
  code: () => "0x6080",
  runtime_code_hash: ({ address }) => RUNTIME_CODE_HASHES.get(address!),
  kernel_account_implementation: () => "0xd6cedde84be40893d153be9d467cd6ad37875b28",
  kernel_account_version: () => "kernel.advanced.v0.3.3",
  kernel_account_entrypoint: () => KERNEL_ENTRY_POINT_V07.address,
  kernel_account_root_validator: () => "0x01845adb2c711129d4f3966735ed98a9f09fc4ce57",
  kernel_ecdsa_owner: () => (root.credential as { address: string }).address,
  kernel_v33_permission_nonce: () => "1",
};
const reads = {
  read: async (request: { type: string; address?: string }) => {
    const answer = answers[request.type];
    if (!answer) throw new Error(`unexpected read ${request.type}`);
    return answer(request);
  },
};

/** The portal: the root approves through the SDK's existing-account preparation. */
function decideV33(forge?: typeof root) {
  return async (request: unknown, requestedAt: number) => {
    const decision = await (
      await prepareKernelPermissionApproval({
        request: request as never,
        chainId: 421_614,
        reads: reads as never,
      })
    ).sign(root.key, requestedAt);
    if (!forge) return decision as never;
    // Another key's signature over the same digest, committed to consistently.
    const installApproval = {
      ...decision.installApproval,
      enableSignature: await forge.key.sign(decision.installApproval.digest),
    };
    return {
      ...decision,
      installApproval,
      capabilityHash: kernelGrantCapabilityHash(installApproval as never),
    } as never;
  };
}

async function portal(options: Parameters<typeof installOAuthPortal>[0]) {
  const installed = await installOAuthPortal({ root, account: ACCOUNT, ...options });
  const { kind: _, ...login } = installed.approvals;
  return { ...installed, login };
}

const ask = (login: Record<string, unknown>) =>
  requestPermissionApproval({
    ...(login as { issuer: string; clientId: string; redirectUri: string }),
    signer: SIGNER,
    policy: POLICY,
    chains: [421_614],
    expiresAt: EXPIRES_AT,
    deviceId: "operator-device",
  });

afterEach(() => vi.unstubAllGlobals());

describe("requestPermissionApproval", () => {
  it("returns a verified Kernel 0.3.3 approval for the caller's passkey", async () => {
    const { login, pars } = await portal({ accountProfile: V33_ACCOUNT, decide: decideV33() });
    const approved = await ask(login);
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail).toMatchObject({ type: "oaath_grant", signer: SIGNER, policy: POLICY });
    const approval = approved.decision.installApproval;
    expect(approval.version).toBe("oaath.kernel.v33-permission-approval/v1");
    expect(approval.account).toBe(ACCOUNT);
    expect(approved.request.operatorCredential).toEqual(SIGNER);
    // The same offline check a backend runs accepts it.
    const signer = approval.packages.at(-1)!;
    const verified = await verifyKernelPermissionApproval({
      approval,
      expected: {
        owner: (root.credential as { address: `0x${string}` }).address,
        account: ACCOUNT,
        permissionId: (approval as { permissionId: `0x${string}` }).permissionId,
        sessionKey: { module: signer.module, publicMaterial: `0x${signer.moduleData.slice(66)}` },
        packages: approval.packages,
      },
    });
    expect(verified.status).toBe("verified");
  });

  it("returns a Kernel 0.4.0 approval for a derived account", async () => {
    const { login } = await portal({});
    const approved = await ask(login);
    expect(approved.decision.installApproval.version).toBe("oaath.kernel.all-chain-approval/v1");
  });

  it("refuses an approval for another signer", async () => {
    const { login } = await portal({
      accountProfile: V33_ACCOUNT,
      decide: decideV33(),
      behaviour: {
        tamper: (request) => {
          request.operatorCredential = {
            ...(SIGNER as object),
            authenticatorIdHash: `0x${"ee".repeat(32)}`,
          };
        },
      },
    });
    await expect(ask(login)).rejects.toMatchObject({ code: "oaath_client_state_conflict" });
  });

  it("refuses a Kernel 0.3.3 approval not signed by the account's root", async () => {
    const { login } = await portal({ accountProfile: V33_ACCOUNT, decide: decideV33(other) });
    await expect(ask(login)).rejects.toMatchObject({
      code: "oaath_client_state_conflict",
      source: "oauth_grant_mismatch",
    });
  });
});
