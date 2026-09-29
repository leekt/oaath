import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { IDBFactory } from "fake-indexeddb";
import { bytesToHex, hashTypedData, keccak256 } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth, type OaathLocalApprovalReview } from "../src/index.js";
import { kernelV33Deployment } from "../src/kernel/deployment/v33.js";
import {
  KERNEL_P256_VERIFIER,
  KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
} from "../src/kernel/modules.js";
import {
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
} from "../src/kernel.js";
import { KERNEL_V4_ENTRY_POINT_V07_CODE_HASH } from "../src/kernel-v4.js";
import { createChainFixture, permissionInput } from "./support/browser.js";

const address = "0xc3a56de6dfc1dcef5113927ec09513918e8c44aa";
function fixture(verifier = false) {
  const account = privateKeyToAccount(generatePrivateKey());
  const deployment = kernelV33Deployment(143);
  const chain = createChainFixture({ chainId: 143 });
  const signTypedData = vi.fn(async (value: Parameters<typeof account.signTypedData>[0]) =>
    account.signTypedData(value),
  );
  const owner = { account, signMessage: vi.fn(account.signMessage), signTypedData };
  const read = vi.fn(async (request: { type: string; address?: string }) => {
    switch (request.type) {
      case "chain_id":
        return 143;
      case "code":
        return "0x6000";
      case "runtime_code_hash":
        if (verifier && request.address === KERNEL_P256_VERIFIER)
          return KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH;
        return request.address === OAATH_KERNEL_V4_VALIDITY_POLICY
          ? OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH
          : KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
      case "kernel_account_implementation":
        return deployment.implementation;
      case "kernel_account_version":
        return "kernel.advanced.v0.3.3";
      case "kernel_account_entrypoint":
        return deployment.entryPoint.address;
      case "kernel_account_root_validator":
        return `0x01${deployment.ecdsaValidator.slice(2)}`;
      case "kernel_ecdsa_owner":
        return account.address.toLowerCase();
      case "kernel_v33_permission_nonce":
        return "1";
      default:
        throw new Error("unexpected read");
    }
  });
  const input = {
    mode: "local" as const,
    owner,
    account: address as `0x${string}`,
    chains: [{ ...chain.capability, reads: { read } }],
    origin: "https://app.example",
  };
  return { input, owner, account, read, chain };
}

afterEach(() => vi.unstubAllGlobals());

const credentialId = "AAECAwQFBgcICQoLDA0ODw";
const passkeySession = Object.freeze({
  kind: "webauthn" as const,
  credential: {
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "webauthn" as const,
    publicKey: bytesToHex(p256.getPublicKey(p256.utils.randomPrivateKey(), false)),
    authenticatorIdHash: keccak256("0x000102030405060708090a0b0c0d0e0f"),
  },
  credentialId,
  rpId: "app.example",
  origin: "https://app.example",
  authenticate: async () => {
    throw new Error("approval must not use the passkey");
  },
});

describe("local wallet realm", () => {
  it("does not create a Grant after a rejected wallet prompt or sign again automatically", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, owner, chain } = fixture();
    owner.signTypedData.mockRejectedValueOnce({ code: 4001 });
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_decision_unavailable",
    });
    expect(await connection.resume()).toBeNull();
    expect(owner.signTypedData).toHaveBeenCalledTimes(1);
    expect(owner.signMessage).not.toHaveBeenCalled();
    expect(chain.sends).toHaveLength(0);
    await realm.close();
  });

  it("refuses a signature from another wallet without activating the Grant", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, owner } = fixture();
    const other = privateKeyToAccount(generatePrivateKey());
    owner.signTypedData.mockImplementation((typedData) => other.signTypedData(typedData));
    const realm = createOAAth(input);
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_signing_failed",
    });
    expect(owner.signTypedData).toHaveBeenCalledTimes(1);
    expect(await connection.resume()).toBeNull();
    await realm.close();
  });

  it("checks the actual account owner before asking the wallet to approve", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, owner, read } = fixture();
    const original = read.getMockImplementation()!;
    read.mockImplementation((request) =>
      request.type === "kernel_ecdsa_owner"
        ? Promise.resolve("0x1111111111111111111111111111111111111111")
        : original(request),
    );
    const realm = createOAAth(input);
    await expect(
      (await realm.connect()).requestPermission(permissionInput()),
    ).rejects.toBeDefined();
    expect(owner.signTypedData).not.toHaveBeenCalled();
    await realm.close();
  });

  it("refuses mismatched all-chain nonces before prompting", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, owner, read } = fixture();
    const second = {
      ...input.chains[0]!,
      chainId: 480,
      reads: {
        read: async (request: Parameters<typeof read>[0]) =>
          request.type === "chain_id"
            ? 480
            : request.type === "kernel_v33_permission_nonce"
              ? "2"
              : read(request),
      },
    };
    const realm = createOAAth({ ...input, chains: [...input.chains, second] });
    await expect(
      (await realm.connect()).requestPermission(permissionInput()),
    ).rejects.toMatchObject({ code: "oaath_client_state_conflict" });
    expect(owner.signTypedData).not.toHaveBeenCalled();
    await realm.close();
  });

  it("lets the application cancel policy display before any wallet signature", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { input, owner } = fixture();
    const realm = createOAAth({
      ...input,
      onApproval: async () => {
        throw new Error("cancelled");
      },
    });
    const connection = await realm.connect();
    await expect(connection.requestPermission(permissionInput())).rejects.toMatchObject({
      code: "oaath_client_decision_unavailable",
    });
    expect(owner.signTypedData).not.toHaveBeenCalled();
    expect(await connection.resume()).toBeNull();
    await realm.close();
  });

  it("refuses an unsupported session kind before opening storage", () => {
    const { input } = fixture();
    expect(() => createOAAth({ ...input, session: { kind: "p256" } } as never)).toThrowError(
      expect.objectContaining({ code: "oaath_client_input_invalid" }),
    );
  });

  it.each([false, true])(
    "binds a caller-supplied passkey session only where its verifier exists (%s)",
    async (verifier) => {
      vi.stubGlobal("indexedDB", new IDBFactory());
      const { input, owner } = fixture(verifier);
      const onApproval = vi.fn(async () => undefined);
      const open = () => createOAAth({ ...input, session: passkeySession, onApproval });
      let realm = open();
      const request = (await realm.connect()).requestPermission(permissionInput());
      if (!verifier) {
        // Fail closed before the owner reviews or signs anything.
        await expect(request).rejects.toMatchObject({
          code: "oaath_client_capability_unsupported",
        });
        expect(onApproval).not.toHaveBeenCalled();
        expect(owner.signTypedData).not.toHaveBeenCalled();
        await realm.close();
        return;
      }
      expect((await request).state).toBe("active");
      expect(realm.binding.operatorCredential).toMatchObject({
        kind: "webauthn",
        publicKey: passkeySession.credential.publicKey,
      });
      const identity = realm.binding;
      await realm.close();
      realm = open();
      expect((await (await realm.connect()).resume())?.state).toBe("active");
      expect(realm.binding).toEqual(identity);
      expect(owner.signTypedData).toHaveBeenCalledTimes(1);
      await realm.close();
    },
  );

  it("approves once, shows the bound policy, and restores the same Grant without any issuer fetch", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const fetch = vi.fn(() => {
      throw new Error("no issuer is allowed");
    });
    vi.stubGlobal("fetch", fetch);
    const { input, owner } = fixture();
    const onApproval = vi.fn(async (_review: Readonly<OaathLocalApprovalReview>) => undefined);
    let realm = createOAAth({ ...input, onApproval });
    let connection = await realm.connect();
    const grant = await connection.requestPermission(permissionInput());
    const identity = realm.binding;
    expect(grant.state).toBe("active");
    expect(owner.signTypedData).toHaveBeenCalledTimes(1);
    expect(owner.signMessage).not.toHaveBeenCalled();
    expect(onApproval).toHaveBeenCalledOnce();
    const review = onApproval.mock.calls[0];
    if (!review) throw new Error("missing review");
    expect(review[0].policy.perChainOperationLimit).toBe(10);
    expect(hashTypedData(review[0].typedData)).toBe(
      hashTypedData(owner.signTypedData.mock.calls[0]![0]),
    );
    await realm.close();
    realm = createOAAth(input);
    connection = await realm.connect();
    const resumed = await connection.resume();
    expect(resumed?.state).toBe("active");
    expect(realm.binding).toEqual(identity);
    expect(owner.signTypedData).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
    await realm.close();
  });
});
