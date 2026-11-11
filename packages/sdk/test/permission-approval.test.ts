/**
 * A root-approved permission for a caller-held session credential through a
 * simulated popup and portal: the PAR names exactly the caller's signer and
 * policy, and only an approval installing exactly that signer, signed by the
 * account's root, is returned. A Kernel 0.3.3 account approves through the
 * SDK's own existing-account preparation.
 */

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  OAATH_MAX_GRANT_CHAINS,
  openAuthorizationPopup,
  requestPermissionApproval,
} from "../src/index.js";
import { KERNEL_ENTRY_POINT_V07 } from "../src/kernel/deployment/v33.js";
import * as M from "../src/kernel/modules.js";
import {
  kernelGrantCapabilityHash,
  verifyKernelPermissionApproval,
} from "../src/kernel/permission/approval.js";
import {
  prepareExistingAccountPermissionApprovalOffline,
  prepareKernelPermissionApproval,
} from "../src/kernel/permission/prepare-approval.js";
import { grantPermissionPackages } from "../src/kernel.js";
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

const ask = (login: Record<string, unknown>, extra: object = {}) =>
  requestPermissionApproval({
    ...(login as { issuer: string; clientId: string; redirectUri: string }),
    ...extra,
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

  it("navigates a popup the caller opened in its gesture", async () => {
    const { login, window } = await portal({ accountProfile: V33_ACCOUNT, decide: decideV33() });
    const popup = openAuthorizationPopup();
    const approved = await ask(login, { popup });
    expect(approved.decision.installApproval.version).toBe(
      "oaath.kernel.v33-permission-approval/v1",
    );
    expect(window.open).toHaveBeenCalledTimes(1);
  });

  it("sends the app's own RPC per chain and refuses one for another chain or over http", async () => {
    const { login, pars } = await portal({ accountProfile: V33_ACCOUNT, decide: decideV33() });
    await ask(login, { rpcUrls: { 421614: "https://arb-sepolia.example/rpc" } });
    const [detail] = JSON.parse([...pars.values()][0]!.get("authorization_details")!);
    expect(detail.rpc_urls).toEqual({ "421614": "https://arb-sepolia.example/rpc" });
    await ask(login, { enableNonce: "1" });
    const sent = JSON.parse([...pars.values()][1]!.get("authorization_details")!)[0];
    expect(sent.enable_nonce).toBe("1");
    for (const enableNonce of ["0", "01", "4294967296", 1])
      await expect(ask(login, { enableNonce })).rejects.toMatchObject({
        code: "oaath_client_input_invalid",
      });
    for (const rpcUrls of [
      { 1: "https://eth.example" },
      { 421614: "http://arb-sepolia.example/rpc" },
      { 421614: "https://key:secret@arb-sepolia.example/rpc" },
      {},
    ])
      await expect(ask(login, { rpcUrls })).rejects.toMatchObject({
        code: "oaath_client_input_invalid",
      });
  });

  it("refuses more than OAATH_MAX_GRANT_CHAINS and shows the issuer's reason", async () => {
    const { login } = await portal({ accountProfile: V33_ACCOUNT, decide: decideV33() });
    const chains = Array.from({ length: OAATH_MAX_GRANT_CHAINS + 1 }, (_, index) => index + 1);
    await expect(
      requestPermissionApproval({
        ...(login as { issuer: string; clientId: string; redirectUri: string }),
        signer: SIGNER,
        policy: POLICY,
        chains,
        expiresAt: EXPIRES_AT,
        deviceId: "operator-device",
      }),
    ).rejects.toMatchObject({ code: "oaath_client_input_invalid" });
    vi.stubGlobal("fetch", async () =>
      Response.json(
        {
          error: "invalid_authorization_details",
          error_description: "chains: at most 256 chain IDs",
        },
        { status: 400 },
      ),
    );
    await expect(ask(login)).rejects.toMatchObject({
      code: "oaath_client_issuer_rejected",
      source: "invalid_authorization_details",
      message: "issuer refused the request: chains: at most 256 chain IDs",
    });
  });

  it("fails typed when a member's request awaits the root", async () => {
    const { login } = await portal({ behaviour: "pending" });
    await expect(ask(login)).rejects.toMatchObject({
      code: "oaath_client_issuer_rejected",
      source: "oauth_permission_pending",
    });
  });
});

describe("prepareExistingAccountPermissionApprovalOffline", () => {
  it("prepares and signs exactly what the read-backed preparation does, reading nothing", async () => {
    const now = Math.floor(Date.now() / 1000);
    const { parsePermissionRequest } = await import("@oaath/protocol");
    const { portalPermissionRequest } = await import("./support/portal-roots.js");
    const request = parsePermissionRequest({
      ...portalPermissionRequest({ root, target: `0x${"aa".repeat(20)}`, requestedAt: now }),
      logicalAccount: V33_ACCOUNT,
    });
    const online = await prepareKernelPermissionApproval({
      request,
      chainId: 421_614,
      reads,
    } as never);
    const offline = prepareExistingAccountPermissionApprovalOffline({
      request,
      chainId: 8453,
      enableNonce: "1",
    } as never);
    expect(offline.signingRequest).toEqual(online.signingRequest);
    const signed = await offline.sign(root.key, now);
    expect(signed).toEqual(await online.sign(root.key, now));
    expect(() =>
      prepareExistingAccountPermissionApprovalOffline({ request, chainId: 8453 } as never),
    ).toThrow();
  });
});

describe("grantPermissionPackages", () => {
  it("derives exactly the relay's packages for every fixture signer and policy", () => {
    const cases = JSON.parse(
      readFileSync(
        new URL("../../../relay/fixtures/grant/kernelGrantApproval.json", import.meta.url),
        "utf8",
      ),
    ) as {
      name: string;
      input: { request: Record<string, unknown> };
      expect: { ok?: { packages: unknown } };
    }[];
    let checked = 0;
    for (const { name, input, expect: expected } of cases) {
      if (!expected.ok) continue;
      const derived = grantPermissionPackages({
        signer: input.request.operatorCredential as never,
        policy: input.request.policy as never,
      });
      expect(derived.packages, name).toEqual(expected.ok.packages);
      expect(derived.permissionId, name).toBe(
        (expected.ok.packages as { internalData: string }[])[0]!.internalData,
      );
      checked += 1;
    }
    expect(checked).toBe(13);
  });
});
