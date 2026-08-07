import { createOperation } from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import {
  deriveOperationId,
  OaathPreparedUserOperationError,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "../src/kernel.js";

const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const SENDER = `0x${"11".repeat(20)}`;
const FACTORY = `0x${"22".repeat(20)}`;
const PAYMASTER = `0x${"33".repeat(20)}`;
const REQUEST_HASH = `0x${"44".repeat(32)}` as const;

function preparationInput(): Record<string, unknown> {
  return {
    kind: "execution",
    grantId: "grant-prepared-vector",
    chainId: 31_337,
    entryPoint: {
      version: "0.7",
      address: ENTRY_POINT,
    },
    userOperation: {
      sender: SENDER,
      nonce: "1",
      callData: "0xabcdef",
      callGasLimit: "100000",
      verificationGasLimit: "200000",
      preVerificationGas: "30000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
      factory: {
        address: FACTORY,
        data: "0x1234",
      },
      paymaster: {
        address: PAYMASTER,
        verificationGasLimit: "40000",
        postOpGasLimit: "50000",
        data: "0xdeadbeef",
      },
    },
  };
}

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectPreparedError(
  action: () => unknown,
  code: OaathPreparedUserOperationError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathPreparedUserOperationError);
    expect((error as OaathPreparedUserOperationError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

function expectInputInvalid(value: unknown): void {
  expectPreparedError(() => prepareUserOperation(value), "prepared_user_operation_input_invalid");
}

function expectRecordInvalid(value: unknown): void {
  expectPreparedError(
    () => parsePreparedUserOperation(value),
    "prepared_user_operation_record_invalid",
  );
}

function mutableUserOperation(input: Record<string, unknown>): Record<string, unknown> {
  return input.userOperation as Record<string, unknown>;
}

describe("prepared UserOperation identity", () => {
  it("matches the accepted EntryPoint 0.7 hash vector and derives the full Operation identity", () => {
    const prepared = prepareUserOperation(preparationInput());

    expect(prepared.userOperationHash).toBe(
      "0xcece6f0173d0c079b6448961644ba4e1177a81344a08b1df61af7f0b4dbda241",
    );
    expect(deriveOperationId(prepared, null)).toEqual({
      kind: "execution",
      grantId: "grant-prepared-vector",
      chainId: 31_337,
      entryPoint: ENTRY_POINT,
      account: SENDER,
      nonce: "1",
      userOperationHash: prepared.userOperationHash,
      requestHash: null,
    });

    const operation = createOperation({
      identity: deriveOperationId(prepared, null),
      preparedAt: 1,
    });
    expect(operation.identity).toEqual(deriveOperationId(prepared, null));
  });

  it("binds strict immutable request provenance outside the UserOperation hash", () => {
    const prepared = prepareUserOperation(preparationInput());
    const directIdentity = deriveOperationId(prepared, null);
    const providerIdentity = deriveOperationId(prepared, REQUEST_HASH);

    expect(prepared).not.toHaveProperty("requestHash");
    expect(providerIdentity).toEqual({
      ...directIdentity,
      requestHash: REQUEST_HASH,
    });
    expect(providerIdentity.userOperationHash).toBe(directIdentity.userOperationHash);
    expect(Object.isFrozen(providerIdentity)).toBe(true);
    expect(Reflect.set(providerIdentity, "requestHash", null)).toBe(false);
    expect(providerIdentity.requestHash).toBe(REQUEST_HASH);

    for (const invalidRequestHash of ["0x12", `0x${"AA".repeat(32)}`, undefined]) {
      expectPreparedError(
        () => Reflect.apply(deriveOperationId, undefined, [prepared, invalidRequestHash]),
        "prepared_user_operation_input_invalid",
      );
    }
  });

  it("round-trips the one JSON-safe current record and freezes every nested value", () => {
    const prepared = prepareUserOperation(preparationInput());
    const restored = parsePreparedUserOperation(clone(prepared));

    expect(restored).toEqual(prepared);
    expect(deriveOperationId(restored, null)).toEqual(deriveOperationId(prepared, null));
    expect(Object.isFrozen(restored)).toBe(true);
    expect(Object.isFrozen(restored.entryPoint)).toBe(true);
    expect(Object.isFrozen(restored.userOperation)).toBe(true);
    expect(Object.isFrozen(restored.userOperation.factory)).toBe(true);
    expect(Object.isFrozen(restored.userOperation.paymaster)).toBe(true);
  });

  it("copies accepted byte arrays once and remains unchanged after every source alias mutates", () => {
    const callData = new Uint8Array([0xab, 0xcd, 0xef]);
    const factoryData = new Uint8Array([0x12, 0x34]);
    const paymasterData = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const input = preparationInput();
    const entryPoint = input.entryPoint as Record<string, unknown>;
    const userOperation = mutableUserOperation(input);
    const factory = userOperation.factory as Record<string, unknown>;
    const paymaster = userOperation.paymaster as Record<string, unknown>;
    userOperation.callData = callData;
    factory.data = factoryData;
    paymaster.data = paymasterData;

    const prepared = prepareUserOperation(input);
    const before = clone(prepared);
    const identity = deriveOperationId(prepared, null);

    input.kind = "revocation";
    input.grantId = "changed";
    input.chainId = 1;
    entryPoint.address = `0x${"44".repeat(20)}`;
    userOperation.sender = `0x${"55".repeat(20)}`;
    userOperation.nonce = "2";
    factory.address = `0x${"66".repeat(20)}`;
    paymaster.address = `0x${"77".repeat(20)}`;
    callData.fill(0);
    factoryData.fill(0);
    paymasterData.fill(0);

    expect(prepared).toEqual(before);
    expect(deriveOperationId(prepared, null)).toEqual(identity);
    expect(prepared.userOperation.callData).toBe("0xabcdef");
    expect(prepared.userOperation.factory?.data).toBe("0x1234");
    expect(prepared.userOperation.paymaster?.data).toBe("0xdeadbeef");
  });

  it("rejects accessors at every boundary without invoking them", () => {
    let calls = 0;
    const topLevel = preparationInput();
    Object.defineProperty(topLevel, "grantId", {
      enumerable: true,
      get() {
        calls += 1;
        return "grant-hostile";
      },
    });
    expectInputInvalid(topLevel);

    const nested = preparationInput();
    Object.defineProperty(nested.entryPoint as object, "address", {
      enumerable: true,
      get() {
        calls += 1;
        return ENTRY_POINT;
      },
    });
    expectInputInvalid(nested);

    const bytes = new Uint8Array([1, 2]);
    Object.defineProperty(bytes, "secret", {
      enumerable: false,
      get() {
        calls += 1;
        return 3;
      },
    });
    const byteInput = preparationInput();
    mutableUserOperation(byteInput).callData = bytes;
    expectInputInvalid(byteInput);
    expect(calls).toBe(0);
  });

  it("rejects missing, extra, symbol, non-enumerable, and prototype-backed fields", () => {
    const extra = preparationInput();
    extra.compatibility = true;
    expectInputInvalid(extra);

    const missing = preparationInput();
    delete missing.grantId;
    expectInputInvalid(missing);

    expectInputInvalid({ ...preparationInput(), [Symbol("hidden")]: true });

    const nonEnumerable = preparationInput();
    Object.defineProperty(nonEnumerable, "hidden", { value: true });
    expectInputInvalid(nonEnumerable);

    const inherited = Object.create({ kind: "execution" }) as Record<string, unknown>;
    Object.assign(inherited, preparationInput());
    expectInputInvalid(inherited);

    const nestedExtra = preparationInput();
    mutableUserOperation(nestedExtra).signature = "0x";
    expectInputInvalid(nestedExtra);
  });

  it("rejects signatures, authorization artifacts, runtime metadata, and capabilities", () => {
    for (const [field, value] of [
      ["signature", "0x"],
      ["authorization", { address: SENDER }],
      ["account", { address: SENDER }],
      ["signer", () => undefined],
      ["transport", { request: () => undefined }],
      ["session", "secret"],
    ] as const) {
      const input = preparationInput();
      mutableUserOperation(input)[field] = value;
      expectInputInvalid(input);
    }
  });

  it("rejects unsupported versions and noncanonical chain, address, byte, and integer fields", () => {
    const badValues: readonly ((input: Record<string, unknown>) => void)[] = [
      (input) => {
        (input.entryPoint as Record<string, unknown>).version = "0.6";
      },
      (input) => {
        input.chainId = 0;
      },
      (input) => {
        input.chainId = Number.MAX_SAFE_INTEGER + 1;
      },
      (input) => {
        (input.entryPoint as Record<string, unknown>).address = ENTRY_POINT.toUpperCase();
      },
      (input) => {
        mutableUserOperation(input).sender = `0x${"00".repeat(20)}`;
      },
      (input) => {
        mutableUserOperation(input).callData = "0xabc";
      },
      (input) => {
        mutableUserOperation(input).callData = "0xAB";
      },
      (input) => {
        mutableUserOperation(input).nonce = "01";
      },
      (input) => {
        mutableUserOperation(input).nonce = ((1n << 256n) + 1n).toString();
      },
      (input) => {
        mutableUserOperation(input).callGasLimit = (1n << 120n).toString();
      },
      (input) => {
        mutableUserOperation(input).preVerificationGas = (1n << 120n).toString();
      },
      (input) => {
        mutableUserOperation(input).maxPriorityFeePerGas = "1000000001";
      },
    ];

    for (const mutate of badValues) {
      const input = preparationInput();
      mutate(input);
      expectInputInvalid(input);
    }
  });

  it("rejects partial or contradictory factory and paymaster shapes", () => {
    const factoryMissingData = preparationInput();
    delete (mutableUserOperation(factoryMissingData).factory as Record<string, unknown>).data;
    expectInputInvalid(factoryMissingData);

    const factoryExtra = preparationInput();
    (mutableUserOperation(factoryExtra).factory as Record<string, unknown>).initCode = "0x";
    expectInputInvalid(factoryExtra);

    const noFactoryWithSidecar = preparationInput();
    mutableUserOperation(noFactoryWithSidecar).factory = null;
    mutableUserOperation(noFactoryWithSidecar).factoryData = "0x1234";
    expectInputInvalid(noFactoryWithSidecar);

    const paymasterMissingGas = preparationInput();
    delete (mutableUserOperation(paymasterMissingGas).paymaster as Record<string, unknown>)
      .postOpGasLimit;
    expectInputInvalid(paymasterMissingGas);

    const noPaymasterWithSidecar = preparationInput();
    mutableUserOperation(noPaymasterWithSidecar).paymaster = null;
    mutableUserOperation(noPaymasterWithSidecar).paymasterData = "0x";
    expectInputInvalid(noPaymasterWithSidecar);

    const eip7702 = preparationInput();
    (mutableUserOperation(eip7702).factory as Record<string, unknown>).address =
      `0x7702${"00".repeat(18)}`;
    expectInputInvalid(eip7702);
  });

  it("accepts explicit absence, including empty calldata and factory/paymaster data", () => {
    const input = preparationInput();
    const userOperation = mutableUserOperation(input);
    userOperation.callData = "0x";
    userOperation.factory = null;
    userOperation.paymaster = null;

    const prepared = prepareUserOperation(input);
    expect(prepared.userOperation.callData).toBe("0x");
    expect(prepared.userOperation.factory).toBeNull();
    expect(prepared.userOperation.paymaster).toBeNull();
    expect(parsePreparedUserOperation(clone(prepared))).toEqual(prepared);
  });

  it("rejects byte-array subclasses, shared memory, extra byte fields, and bytes in records", () => {
    class BytesSubclass extends Uint8Array {}
    const subclass = preparationInput();
    mutableUserOperation(subclass).callData = new BytesSubclass([1]);
    expectInputInvalid(subclass);

    const extra = new Uint8Array([1]);
    Object.defineProperty(extra, "extra", { enumerable: true, value: 1 });
    const extraInput = preparationInput();
    mutableUserOperation(extraInput).callData = extra;
    expectInputInvalid(extraInput);

    if (typeof SharedArrayBuffer !== "undefined") {
      const shared = preparationInput();
      mutableUserOperation(shared).callData = new Uint8Array(new SharedArrayBuffer(1));
      expectInputInvalid(shared);
    }

    const record = clone(prepareUserOperation(preparationInput())) as unknown as Record<
      string,
      unknown
    >;
    mutableUserOperation(record).callData = new Uint8Array([0xab]);
    expectRecordInvalid(record);
  });

  it("recomputes the hash and rejects every changed ERC-4337 identity field", () => {
    const prepared = prepareUserOperation(preparationInput());
    const substitutions: readonly ((record: Record<string, unknown>) => void)[] = [
      (record) => {
        record.chainId = 31_338;
      },
      (record) => {
        (record.entryPoint as Record<string, unknown>).address = `0x${"44".repeat(20)}`;
      },
      (record) => {
        mutableUserOperation(record).sender = `0x${"55".repeat(20)}`;
      },
      (record) => {
        mutableUserOperation(record).nonce = "2";
      },
      (record) => {
        mutableUserOperation(record).callData = "0x00";
      },
      (record) => {
        mutableUserOperation(record).callGasLimit = "100001";
      },
      (record) => {
        mutableUserOperation(record).verificationGasLimit = "200001";
      },
      (record) => {
        mutableUserOperation(record).preVerificationGas = "30001";
      },
      (record) => {
        mutableUserOperation(record).maxFeePerGas = "1000000001";
      },
      (record) => {
        mutableUserOperation(record).maxPriorityFeePerGas = "100000001";
      },
      (record) => {
        (mutableUserOperation(record).factory as Record<string, unknown>).data = "0x12";
      },
      (record) => {
        (mutableUserOperation(record).factory as Record<string, unknown>).address =
          `0x${"66".repeat(20)}`;
      },
      (record) => {
        mutableUserOperation(record).factory = null;
      },
      (record) => {
        (mutableUserOperation(record).paymaster as Record<string, unknown>).data = "0xde";
      },
      (record) => {
        (mutableUserOperation(record).paymaster as Record<string, unknown>).address =
          `0x${"77".repeat(20)}`;
      },
      (record) => {
        (mutableUserOperation(record).paymaster as Record<string, unknown>).verificationGasLimit =
          "40001";
      },
      (record) => {
        (mutableUserOperation(record).paymaster as Record<string, unknown>).postOpGasLimit =
          "50001";
      },
      (record) => {
        mutableUserOperation(record).paymaster = null;
      },
      (record) => {
        record.userOperationHash = `0x${"99".repeat(32)}`;
      },
    ];

    for (const substitute of substitutions) {
      const record = clone(prepared) as unknown as Record<string, unknown>;
      substitute(record);
      expectRecordInvalid(record);
    }
  });

  it("keeps kind and grant association in the compound identity, outside the ERC-4337 hash", () => {
    const prepared = prepareUserOperation(preparationInput());
    const changed = clone(prepared) as unknown as Record<string, unknown>;
    changed.kind = "revocation";
    changed.grantId = "another-grant";

    const changedPrepared = parsePreparedUserOperation(changed);
    expect(changedPrepared.userOperationHash).toBe(prepared.userOperationHash);
    expect(deriveOperationId(changedPrepared, null)).not.toEqual(deriveOperationId(prepared, null));
    expect(deriveOperationId(changedPrepared, null)).toMatchObject({
      kind: "revocation",
      grantId: "another-grant",
    });
  });

  it("rejects wrong record versions, unknown record fields, and malformed recorded hashes", () => {
    const prepared = prepareUserOperation(preparationInput());
    expectRecordInvalid({ ...prepared, version: "oaath.prepared-user-operation/v0" });
    expectRecordInvalid({ ...prepared, compatibility: true });
    expectRecordInvalid({ ...prepared, userOperationHash: "0x12" });

    const missing = clone(prepared) as unknown as Record<string, unknown>;
    delete missing.userOperationHash;
    expectRecordInvalid(missing);

    expectRecordInvalid({ ...prepared, [Symbol("hidden")]: true });
  });
});
