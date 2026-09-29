import { encodeErrorResult } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { isAccountValidationRejection, OaathRpcError, rpcOwner } from "../src/viem/rpc.js";

const data = encodeErrorResult({
  abi: entryPoint07Abi,
  errorName: "FailedOpWithRevert",
  args: [0n, "AA23 reverted", "0x"],
});

describe("account-validation rejection evidence", () => {
  it.each([
    { method: "eth_estimateUserOperationGas", code: -32500, data, status: 200, expected: true },
    { method: "eth_sendUserOperation", code: -32500, data, status: 200, expected: false },
    { method: "eth_estimateUserOperationGas", code: -32603, data, status: 200, expected: false },
    {
      method: "eth_estimateUserOperationGas",
      code: -32500,
      data: `${data}00`,
      status: 200,
      expected: false,
    },
    {
      method: "eth_estimateUserOperationGas",
      code: -32500,
      data: "0x",
      status: 200,
      expected: false,
    },
    { method: "eth_estimateUserOperationGas", code: -32500, data, status: 503, expected: false },
  ])(
    "binds the rejection to its exact method, error code and canonical bytes: $method/$code/$status",
    async ({ method, code, data, status, expected }) => {
      const owner = rpcOwner({
        retry: { attempts: 1 },
        fetch: async (request) => {
          const { id } = await request.json();
          return Response.json(
            {
              jsonrpc: "2.0",
              id,
              error: { code, message: "AA23 private provider material", data },
            },
            { status },
          );
        },
      });
      const error = await owner
        .pool(
          ["https://fixture.test"],
          143,
          [method],
          false,
        )(method)
        .catch((error: unknown) => error);
      expect(isAccountValidationRejection(error)).toBe(expected);
      expect(JSON.stringify(error)).not.toContain("private provider material");
    },
  );

  it("does not let a diagnostic or caller-created error grant fallback authority", () => {
    const diagnostic = {
      kind: "validation_gas_likely_insufficient",
      verificationGasLimit: "2000000",
    } as const;
    expect(
      isAccountValidationRejection(new OaathRpcError("oaath_rpc_rejected", -32500, diagnostic)),
    ).toBe(false);
    expect(
      isAccountValidationRejection({
        name: "OaathRpcError",
        code: "oaath_rpc_rejected",
        rpcCode: -32500,
        diagnostic,
      }),
    ).toBe(false);
  });
});
