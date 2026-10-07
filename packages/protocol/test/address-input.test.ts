import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import {
  captureServiceAccount,
  createKernelReplayableInstallTypedData,
  createOperation,
  encodeGrantPolicy,
  encodeKernelInstallNonceInvalidationCall,
  encodeKernelPermissionUninstallCalls,
  hashCanonicalEip712TypedData,
  hashGrantPolicy,
  hashGrantPolicyCalls,
  parseGrantPolicy,
  parseOwnerCredentialProfile,
} from "../src/index.js";

const lower = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const checked = getAddress(lower);
const upper = `0x${lower.slice(2).toUpperCase()}` as const;
const wrong = checked.replace(/[a-f]/u, (letter) => letter.toUpperCase()) as `0x${string}`;
const policy = (target: `0x${string}`) => ({
  version: "oaath.grant-policy/v2" as const,
  calls: [{ target, selector: "0x12345678" as const, valueLimit: "1", argumentEquals: [] }],
  validAfter: 0,
  validUntil: null,
  perChainOperationLimit: { count: 1, intervalSeconds: null },
});
const owner = (address: `0x${string}`) => ({
  version: "oaath.owner-credential-profile/v1" as const,
  kind: "ecdsa" as const,
  address,
});
const packages = (module: `0x${string}`) =>
  ([5, 6] as const).map((moduleType) => ({
    moduleType,
    module,
    moduleData: `0x${"11".repeat(32)}` as const,
    internalData: "0x12345678" as const,
  }));

describe("canonical address inputs", () => {
  const paths: [string, (address: `0x${string}`) => unknown][] = [
    ["policy target", (address) => parseGrantPolicy(policy(address))],
    ["owner credential address", (address) => parseOwnerCredentialProfile(owner(address))],
    [
      "operation identity account",
      (address) =>
        createOperation({
          identity: {
            kind: "execution",
            grantId: "grant-address",
            chainId: 1,
            entryPoint: lower,
            account: address,
            nonce: "0",
            userOperationHash: `0x${"11".repeat(32)}`,
            requestHash: null,
          },
          preparedAt: 1,
        }),
    ],
    [
      "service account owner validator",
      (address) =>
        captureServiceAccount(
          {
            version: "oaath.kernel-account-profile/v1",
            kind: "kernel",
            accountIndex: "0",
            kernelVersion: "0.4.0",
            factoryRoute: "kernel_factory",
            entryPoint: { version: "0.9" },
            ownerCredential: owner(lower),
          },
          address,
          new WeakSet(),
          (message) => {
            throw new Error(message);
          },
        ),
    ],
    [
      "Kernel install account",
      (address) =>
        createKernelReplayableInstallTypedData({
          account: address,
          nonce: "0",
          packages: packages(lower),
        }),
    ],
    [
      "Kernel install module",
      (address) =>
        createKernelReplayableInstallTypedData({
          account: lower,
          nonce: "0",
          packages: packages(address),
        }),
    ],
    [
      "Kernel install nonce account",
      (address) =>
        encodeKernelInstallNonceInvalidationCall({
          account: address,
          installNonce: "0",
        }),
    ],
    [
      "Kernel permission uninstall account",
      (address) =>
        encodeKernelPermissionUninstallCalls({
          account: address,
          packages: packages(lower),
        }),
    ],
  ];
  it.each(paths)("normalizes %s without changing the captured artifact", (_label, capture) => {
    for (const address of [lower, checked, upper] as const)
      expect(capture(address)).toEqual(capture(lower));
  });
  it.each(paths)("rejects a wrong checksum in %s and names the field", (_label, capture) => {
    expect(wrong.toLowerCase()).toBe(lower);
    expect(wrong).not.toBe(checked);
    expect(() => capture(wrong)).toThrow(
      /.+(?:address|target|account|module|validator).+checksum/u,
    );
  });
  it("keeps policy encodings, policy hashes, and EIP-712 digests identical", () => {
    for (const address of [checked, upper]) {
      expect(encodeGrantPolicy(policy(address))).toBe(encodeGrantPolicy(policy(lower)));
      expect(hashGrantPolicy(policy(address))).toBe(hashGrantPolicy(policy(lower)));
      expect(hashGrantPolicyCalls(policy(address).calls)).toBe(
        hashGrantPolicyCalls(policy(lower).calls),
      );
      const typedData = (account: `0x${string}`) =>
        createKernelReplayableInstallTypedData({
          account,
          nonce: "0",
          packages: packages(account),
        });
      expect(hashCanonicalEip712TypedData(typedData(address))).toBe(
        hashCanonicalEip712TypedData(typedData(lower)),
      );
    }
  });
});
