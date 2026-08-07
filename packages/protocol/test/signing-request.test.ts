import { describe, expect, it } from "vitest";
import {
  encodeOwnerSigningRequest,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  OaathProtocolError,
  parseOwnerSigningRequest,
} from "../src/index.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const OWNER_PUBLIC_KEY =
  "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const DIGEST = "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2";

function mailTypedData() {
  return {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
      Mail: [
        { name: "from", type: "Person" },
        { name: "to", type: "Person" },
        { name: "contents", type: "string" },
      ],
    },
    primaryType: "Mail",
    domain: {
      name: "Ether Mail",
      version: "1",
      chainId: "1",
      verifyingContract: "0xcccccccccccccccccccccccccccccccccccccccc",
    },
    message: {
      from: { name: "Cow", wallet: "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826" },
      to: { name: "Bob", wallet: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      contents: "Hello, Bob!",
    },
  };
}

function eip712Request() {
  return {
    version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
    kind: "eip712",
    purpose: "application",
    signer: {
      account: ACCOUNT,
      ownerCredential: {
        version: "oaath.owner-credential-profile/v1",
        kind: "p256",
        publicKey: OWNER_PUBLIC_KEY,
      },
    },
    typedData: mailTypedData(),
    expectedDigest: DIGEST,
    replay: { nonce: "0", deadline: null },
  };
}

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function fieldAt<Field>(fields: Field[], index: number): Field {
  const field = fields[index];
  if (field === undefined) throw new Error(`missing test field ${index}`);
  return field;
}

function expectInvalid(value: unknown): void {
  try {
    parseOwnerSigningRequest(value);
    throw new Error("expected owner signing request to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "signing_request_invalid" });
  }
}

describe("owner signing request", () => {
  it("captures the official EIP-712 Mail vector immutably and binds its exact request", () => {
    const input = eip712Request();
    const captured = parseOwnerSigningRequest(input);
    expect(captured.kind).toBe("eip712");
    if (captured.kind !== "eip712") throw new Error("wrong captured kind");

    expect(hashCanonicalEip712TypedData(captured.typedData)).toBe(DIGEST);
    expect(hashOwnerSigningRequest(captured)).toBe(
      "0x1588b0d137ab76a1f63adc58befd1137642312ea71cdca34659851e4796488ba",
    );
    expect(encodeOwnerSigningRequest(captured)).toMatch(/^0x[0-9a-f]+$/u);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.signer)).toBe(true);
    expect(Object.isFrozen(captured.signer.ownerCredential)).toBe(true);
    expect(Object.isFrozen(captured.typedData.types.Mail)).toBe(true);
    expect(Object.isFrozen(captured.typedData.message.from)).toBe(true);

    fieldAt(input.typedData.types.Mail, 2).name = "changed";
    input.typedData.domain.name = "Changed";
    input.typedData.message.from.name = "Mallory";
    input.signer.account = "0x3333333333333333333333333333333333333333";
    expect(hashCanonicalEip712TypedData(captured.typedData)).toBe(DIGEST);
    expect(captured.signer.account).toBe(ACCOUNT);
  });

  it("captures the complete bounded atomic, struct, and array type family", () => {
    const typedData = {
      types: {
        EIP712Domain: [
          { name: "chainId", type: "uint256" },
          { name: "verifyingContract", type: "address" },
        ],
        Item: [
          { name: "delta", type: "int8" },
          { name: "flag", type: "bool" },
        ],
        Payload: [
          { name: "maximum", type: "uint256" },
          { name: "fixedBytes", type: "bytes32" },
          { name: "dynamicBytes", type: "bytes" },
          { name: "label", type: "string" },
          { name: "items", type: "Item[2][]" },
        ],
      },
      primaryType: "Payload",
      domain: { chainId: "1", verifyingContract: ACCOUNT },
      message: {
        maximum: (2n ** 256n - 1n).toString(),
        fixedBytes: `0x${"ab".repeat(32)}`,
        dynamicBytes: "0x00ff",
        label: "bounded payload",
        items: [
          [
            { delta: "-128", flag: false },
            { delta: "127", flag: true },
          ],
          [
            { delta: "0", flag: true },
            { delta: "1", flag: false },
          ],
        ],
      },
    };
    const hash = hashCanonicalEip712TypedData(typedData);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(hashCanonicalEip712TypedData(clone(typedData))).toBe(hash);
  });

  it("rejects noncanonical built-in widths before accepted data reaches encoding", () => {
    for (const type of ["uint08", "int08", "bytes01"]) {
      const request = clone(eip712Request());
      request.typedData.types = {
        EIP712Domain: request.typedData.types.EIP712Domain,
        Envelope: [{ name: "payload", type }],
        [type]: [{ name: "value", type: "uint8" }],
      } as never;
      request.typedData.primaryType = "Envelope";
      request.typedData.domain = {
        name: "Ether Mail",
        version: "1",
        chainId: "1",
        verifyingContract: "0xcccccccccccccccccccccccccccccccccccccccc",
      };
      request.typedData.message = { payload: { value: "1" } } as never;
      expectInvalid(request);
    }

    const captured = parseOwnerSigningRequest(eip712Request());
    expect(encodeOwnerSigningRequest(captured)).toMatch(/^0x[0-9a-f]+$/u);
    expect(hashOwnerSigningRequest(captured)).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it("binds every authority, digest, purpose, and replay field in the request hash", () => {
    const base = eip712Request();
    const expected = hashOwnerSigningRequest(base);
    const variants = [
      { ...clone(base), purpose: "permit" },
      {
        ...clone(base),
        signer: { ...clone(base.signer), account: "0x3333333333333333333333333333333333333333" },
      },
      {
        ...clone(base),
        signer: {
          ...clone(base.signer),
          ownerCredential: {
            version: "oaath.owner-credential-profile/v1",
            kind: "ecdsa",
            address: OWNER_PUBLIC_KEY.slice(0, 42),
          },
        },
      },
      {
        ...clone(base),
        typedData: {
          ...clone(base.typedData),
          message: { ...clone(base.typedData.message), contents: "Changed" },
        },
      },
      { ...clone(base), expectedDigest: `0x${"55".repeat(32)}` },
      { ...clone(base), replay: { nonce: null, deadline: null } },
      { ...clone(base), replay: { nonce: "0", deadline: "0" } },
    ];
    for (const variant of variants) expect(hashOwnerSigningRequest(variant)).not.toBe(expected);
  });

  it("keeps every raw digest readable but terminally reject-only", () => {
    const raw = parseOwnerSigningRequest({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "raw-digest",
      digest: `0x${"44".repeat(32)}`,
      reason: "No device-side derivation is available",
      decision: "reject-only",
    });
    expect(raw).toEqual({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "raw-digest",
      digest: `0x${"44".repeat(32)}`,
      reason: "No device-side derivation is available",
      decision: "reject-only",
    });
    expect(Object.isFrozen(raw)).toBe(true);
    expect(hashOwnerSigningRequest(raw)).toBe(
      "0xc54b4026d0a405712135675831934bf49451ca293a1d0d528d26979e7c0fc40a",
    );
    expectInvalid({ ...raw, decision: "approve-or-reject" });
  });

  it("rejects malformed, unsupported, aliased, and over-limit inputs", () => {
    const cases: unknown[] = [];
    const wrongVersion = clone(eip712Request());
    wrongVersion.version = "oaath.owner-signing-request/v2" as never;
    cases.push(wrongVersion);
    const wrongPurpose = clone(eip712Request());
    wrongPurpose.purpose = "generic" as never;
    cases.push(wrongPurpose);
    const zeroSigner = clone(eip712Request());
    zeroSigner.signer.account = `0x${"00".repeat(20)}`;
    cases.push(zeroSigner);
    cases.push({ ...eip712Request(), extra: true });

    const uintAlias = clone(eip712Request());
    fieldAt(uintAlias.typedData.types.EIP712Domain, 2).type = "uint";
    cases.push(uintAlias);
    const unknownType = clone(eip712Request());
    fieldAt(unknownType.typedData.types.Mail, 2).type = "Missing";
    cases.push(unknownType);
    const reservedField = clone(eip712Request());
    fieldAt(reservedField.typedData.types.Mail, 2).name = "__proto__";
    cases.push(reservedField);
    const unusedType = clone(eip712Request());
    Object.assign(unusedType.typedData.types, { Unused: [{ name: "value", type: "uint8" }] });
    cases.push(unusedType);
    const extraStructField = clone(eip712Request());
    Object.assign(extraStructField.typedData.message.from, { extra: "no" });
    cases.push(extraStructField);
    const uppercaseAddress = clone(eip712Request());
    uppercaseAddress.typedData.message.from.wallet = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";
    cases.push(uppercaseAddress);

    const fixedMismatch = clone(eip712Request());
    fieldAt(fixedMismatch.typedData.types.Mail, 2).type = "bytes2";
    fixedMismatch.typedData.message.contents = "0x00";
    cases.push(fixedMismatch);
    const uintOverflow = clone(eip712Request());
    fieldAt(uintOverflow.typedData.types.Mail, 2).type = "uint8";
    uintOverflow.typedData.message.contents = "256";
    cases.push(uintOverflow);
    const signedOverflow = clone(eip712Request());
    fieldAt(signedOverflow.typedData.types.Mail, 2).type = "int8";
    signedOverflow.typedData.message.contents = "-129";
    cases.push(signedOverflow);
    const noncanonical = clone(eip712Request());
    fieldAt(noncanonical.typedData.types.Mail, 2).type = "uint256";
    noncanonical.typedData.message.contents = "01";
    cases.push(noncanonical);
    const oversized = clone(eip712Request());
    oversized.typedData.message.contents = "x".repeat(16 * 1024 + 1);
    cases.push(oversized);
    const tooMany = clone(eip712Request());
    fieldAt(tooMany.typedData.types.Mail, 2).type = "uint8[]";
    tooMany.typedData.message.contents = Array.from({ length: 257 }, () => "0") as never;
    cases.push(tooMany);
    const tooDeep = clone(eip712Request());
    fieldAt(tooDeep.typedData.types.Mail, 2).type = `uint8${"[]".repeat(17)}`;
    let deep: unknown = "1";
    for (let index = 0; index < 17; index += 1) deep = [deep];
    tooDeep.typedData.message.contents = deep as never;
    cases.push(tooDeep);

    const sparse = clone(eip712Request());
    const fields = sparse.typedData.types.Mail;
    delete fields[1];
    cases.push(sparse);
    for (const value of cases) expectInvalid(value);

    const aliased = eip712Request();
    aliased.typedData.message.from = aliased.typedData.message.to;
    expectInvalid(aliased);

    const cyclic = eip712Request();
    (cyclic.typedData.message.from as Record<string, unknown>).name = cyclic.typedData.message.from;
    expectInvalid(cyclic);
  });

  it("fails hostile descriptors and reflection closed without invoking getters", () => {
    let getterCalls = 0;
    const accessor = eip712Request() as Record<string, unknown>;
    Object.defineProperty(accessor, "kind", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "eip712";
      },
    });
    expectInvalid(accessor);
    expect(getterCalls).toBe(0);

    expectInvalid(
      new Proxy(eip712Request(), {
        ownKeys() {
          throw new Error("hostile secret");
        },
      }),
    );

    const symbol = eip712Request() as Record<PropertyKey, unknown>;
    symbol[Symbol("hidden")] = true;
    expectInvalid(symbol);
  });
});
