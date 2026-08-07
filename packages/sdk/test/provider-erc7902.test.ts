/** Draft ERC-7902 static-paymaster capture and exact identity binding. */
import { describe, expect, it } from "vitest";
import {
  captureErc7902StaticPaymasterConfiguration,
  ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN,
  ERC7902_STATIC_PAYMASTER_LIMITS,
  hashErc7902StaticPaymasterConfiguration,
  OaathRoutingError,
} from "../src/advanced.js";
import { prepareUserOperation } from "../src/kernel.js";

const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const SENDER = `0x${"11".repeat(20)}`;
const FACTORY = `0x${"22".repeat(20)}`;
const PAYMASTER = `0x${"33".repeat(20)}`;

function configuration(): Record<string, unknown> {
  return {
    paymaster: PAYMASTER,
    paymasterData: "0xdeadbeef",
    paymasterValidationGasLimit: "0x9c40",
    paymasterPostOpGasLimit: "0xc350",
  };
}

function preparation(paymaster: unknown): Record<string, unknown> {
  return {
    kind: "execution",
    grantId: "erc7902-static-paymaster",
    chainId: 31_337,
    entryPoint: { version: "0.7", address: ENTRY_POINT },
    userOperation: {
      sender: SENDER,
      nonce: "7",
      callData: "0xabcdef",
      callGasLimit: "100000",
      verificationGasLimit: "200000",
      preVerificationGas: "30000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
      factory: { address: FACTORY, data: "0x1234" },
      paymaster,
    },
  };
}

function expectCapabilityInvalid(value: unknown): void {
  try {
    captureErc7902StaticPaymasterConfiguration(value);
  } catch (error) {
    expect(error).toBeInstanceOf(OaathRoutingError);
    expect((error as OaathRoutingError).code).toBe("routing_capability_invalid");
    return;
  }
  throw new Error("expected invalid ERC-7902 static paymaster configuration");
}

describe("ERC-7902 static paymaster capture", () => {
  it("maps the literal Draft fields into the exact existing PreparedPaymaster owner", () => {
    const source: Record<string, unknown> = { ...configuration(), optional: true };
    const captured = captureErc7902StaticPaymasterConfiguration(source);

    expect(captured).toEqual({
      optional: true,
      paymaster: {
        address: PAYMASTER,
        verificationGasLimit: "40000",
        postOpGasLimit: "50000",
        data: "0xdeadbeef",
      },
    });
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.paymaster)).toBe(true);

    source.optional = false;
    source.paymaster = `0x${"44".repeat(20)}`;
    source.paymasterData = "0x";
    source.paymasterValidationGasLimit = "0x0";
    expect(captured).toEqual({
      optional: true,
      paymaster: {
        address: PAYMASTER,
        verificationGasLimit: "40000",
        postOpGasLimit: "50000",
        data: "0xdeadbeef",
      },
    });
  });

  it("binds all four mapped fields into the existing prepared UserOperation identity", () => {
    const captured = captureErc7902StaticPaymasterConfiguration(configuration());
    const withoutPaymaster = prepareUserOperation(preparation(null));
    const withPaymaster = prepareUserOperation(preparation(captured.paymaster));

    expect(captured.optional).toBe(false);
    expect(withPaymaster.userOperation).toEqual({
      ...withoutPaymaster.userOperation,
      paymaster: captured.paymaster,
    });
    expect(withPaymaster.userOperationHash).not.toBe(withoutPaymaster.userOperationHash);
  });

  it("commits every normalized paymaster field under one domain but excludes negotiation", () => {
    const baseline = hashErc7902StaticPaymasterConfiguration(configuration());
    expect(ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN).toBe(
      "@oaath/sdk:erc-7902-static-paymaster-configuration/v1",
    );
    expect(baseline).toBe("0x70a35e6c247838ac3ef02bdd886943bec3426ceed1692726aee6da0de816a031");
    expect(hashErc7902StaticPaymasterConfiguration({ ...configuration(), optional: true })).toBe(
      baseline,
    );

    for (const changed of [
      { ...configuration(), paymaster: `0x${"44".repeat(20)}` },
      { ...configuration(), paymasterData: "0xdeadbe00" },
      { ...configuration(), paymasterValidationGasLimit: "0x9c41" },
      { ...configuration(), paymasterPostOpGasLimit: "0xc351" },
    ]) {
      expect(hashErc7902StaticPaymasterConfiguration(changed)).not.toBe(baseline);
    }
  });

  it("accepts the exact numeric and data boundaries", () => {
    const maximum = `0x${"f".repeat(30)}`;
    const data = `0x${"ab".repeat(ERC7902_STATIC_PAYMASTER_LIMITS.paymasterDataBytes)}`;
    expect(
      captureErc7902StaticPaymasterConfiguration({
        ...configuration(),
        paymasterData: data,
        paymasterValidationGasLimit: "0x0",
        paymasterPostOpGasLimit: maximum,
      }),
    ).toEqual({
      optional: false,
      paymaster: {
        address: PAYMASTER,
        verificationGasLimit: "0",
        postOpGasLimit: ((1n << 120n) - 1n).toString(10),
        data,
      },
    });
  });

  it("rejects missing, extra, aliased, malformed, noncanonical, and out-of-bounds fields", () => {
    const missing = configuration();
    delete missing.paymasterData;
    const alias = configuration();
    delete alias.paymasterValidationGasLimit;
    alias.paymasterVerificationGasLimit = "0x9c40";
    const aboveUint120 = `0x1${"0".repeat(30)}`;
    const oversizedData = `0x${"00".repeat(ERC7902_STATIC_PAYMASTER_LIMITS.paymasterDataBytes + 1)}`;

    for (const value of [
      null,
      [],
      missing,
      { ...configuration(), extra: true },
      alias,
      { ...configuration(), optional: "true" },
      { ...configuration(), paymaster: `0x${"00".repeat(20)}` },
      { ...configuration(), paymaster: `0x${"AA".repeat(20)}` },
      { ...configuration(), paymaster: "0x33" },
      { ...configuration(), paymasterData: "0x0" },
      { ...configuration(), paymasterData: "0xDEAD" },
      { ...configuration(), paymasterData: oversizedData },
      { ...configuration(), paymasterValidationGasLimit: "0x00" },
      { ...configuration(), paymasterValidationGasLimit: "0xA" },
      { ...configuration(), paymasterValidationGasLimit: aboveUint120 },
      { ...configuration(), paymasterPostOpGasLimit: 1 },
      { ...configuration(), paymasterPostOpGasLimit: "1" },
    ]) {
      expectCapabilityInvalid(value);
    }
  });

  it("rejects accessors and hostile reflection without invoking or exposing them", () => {
    let reads = 0;
    const accessor = configuration();
    Object.defineProperty(accessor, "paymaster", {
      enumerable: true,
      get() {
        reads += 1;
        return PAYMASTER;
      },
    });
    expectCapabilityInvalid(accessor);
    expect(reads).toBe(0);

    const hostile = new Proxy(configuration(), {
      ownKeys() {
        throw new Error("private provider detail");
      },
    });
    expectCapabilityInvalid(hostile);
  });
});
