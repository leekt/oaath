import { describe, expect, it } from "vitest";
import { captureLocalAnvilRecovery } from "../src/anvil-recovery.js";

const descriptor = {
  version: "oaath.local-anvil-recovery/v1",
  existingAccount: null,
  owner: `0x${"11".repeat(20)}`,
  session: `0x${"22".repeat(20)}`,
  chains: [
    {
      chainId: 421614,
      rpcUrl: "http://127.0.0.1:12345",
      validator: `0x${"33".repeat(20)}`,
      feePayer: { address: `0x${"44".repeat(20)}`, balance: "1000000" },
    },
  ],
};

describe("local recovery descriptor", () => {
  it("owns an immutable snapshot of public environment facts", () => {
    const source = structuredClone(descriptor);
    const captured = captureLocalAnvilRecovery(source);
    const first = source.chains[0];
    if (!first) throw new Error("test_chain_missing");
    first.rpcUrl = "http://127.0.0.1:23456";
    expect(captured).toEqual(descriptor);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.chains)).toBe(true);
    expect(Object.isFrozen(captured.chains[0]?.feePayer)).toBe(true);
  });

  it("rejects nonlocal endpoints and extra material before opening any resources", () => {
    for (const rpcUrl of [
      "https://example.com",
      "http://localhost:12345",
      "http://127.0.0.1:0",
      "http://127.0.0.1:70000",
      "http://user:password@127.0.0.1:12345",
      "http://127.0.0.1:12345/path",
      "http://127.0.0.1:12345?token=redacted",
    ]) {
      expect(() =>
        captureLocalAnvilRecovery({ ...descriptor, chains: [{ ...descriptor.chains[0], rpcUrl }] }),
      ).toThrow("local_fixture_recovery_invalid");
    }
    for (const value of [
      { ...descriptor, version: "unsupported" },
      { ...descriptor, existingAccount: "0x1234" },
      { ...descriptor, unrelated: true },
      { ...descriptor, chains: [] },
      { ...descriptor, chains: [descriptor.chains[0], descriptor.chains[0]] },
      {
        ...descriptor,
        get owner() {
          throw new Error("must not escape");
        },
      },
    ])
      expect(() => captureLocalAnvilRecovery(value)).toThrow("local_fixture_recovery_invalid");
  });
});
