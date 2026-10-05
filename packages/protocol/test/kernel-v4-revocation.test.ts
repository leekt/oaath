import { readFileSync } from "node:fs";
import {
  getUserOperationHash,
  toUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import {
  type KernelRevocationOperation,
  parseKernelRevocationSigningRequest,
} from "../src/index.js";

interface Entry {
  readonly name: string;
  readonly effect: string;
  readonly chainId: number;
  readonly entryPoint: `0x${string}`;
  readonly operation: KernelRevocationOperation;
  readonly expectedDigest: `0x${string}`;
}
const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/kernel-revocation-operation.json", import.meta.url), "utf8"),
) as {
  installProjection: { scope: { request: unknown } };
  permissionRequest: unknown;
  valid: Entry[];
  forbiddenCalls: Entry[];
};

function request({ name: _name, ...entry }: Entry) {
  return {
    version: "oaath.kernel-revocation-signing-request/v2",
    kind: "kernel-revocation",
    permissionRequest: fixture.permissionRequest,
    install: fixture.installProjection.scope.request,
    ...entry,
  };
}

describe("unsigned revocation fixture shared with the native phone", () => {
  it.each(fixture.valid)("accepts $name", (entry) => {
    expect(parseKernelRevocationSigningRequest(request(entry))).toEqual(request(entry));
  });

  it.each(fixture.forbiddenCalls)("refuses $name despite its correct hash", (entry) => {
    const operation = entry.operation;
    // Runtime packed conversion; viem's declaration retains the input shape.
    const userOperation = toUserOperation({
      ...operation,
      nonce: BigInt(operation.nonce),
      preVerificationGas: BigInt(operation.preVerificationGas),
      signature: "0x",
    }) as unknown as UserOperation<"0.9">;
    expect(
      getUserOperationHash({
        chainId: entry.chainId,
        entryPointAddress: entry.entryPoint,
        entryPointVersion: "0.9",
        userOperation,
      }),
    ).toBe(entry.expectedDigest);
    expect(() => parseKernelRevocationSigningRequest(request(entry))).toThrowError(
      expect.objectContaining({ code: "signing_request_invalid" }),
    );
  });
});
