import { encodeErrorResult } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { OaathRpcError, rpcOwner } from "../src/viem/rpc.js";
import {
  classifyUserOperationError,
  parseUserOperationFailure,
  serializeUserOperationFailure,
} from "../src/viem.js";

const stages = ["estimate", "sponsor", "send", "receipt"] as const;
describe("UserOperation failure classification", () => {
  it.each([
    ["AA13", "deployment"],
    ["AA21", "insufficient-funds"],
    ["AA23", "account-validation"],
    ["AA24", "invalid-signature"],
    ["AA25", "nonce"],
    ["AA31", "insufficient-funds"],
    ["AA33", "paymaster-validation"],
    ["AA34", "invalid-signature"],
  ])("classifies %s without copying prose", (entryPointCode, code) => {
    const cause = { code: -32500, message: `${entryPointCode} untrusted-provider-detail` };
    const error = classifyUserOperationError({ stage: "send", error: cause });
    expect(error).toMatchObject({ stage: "send", code, entryPointCode, retryable: false });
    expect(error.cause).toBe(cause);
    expect(`${error}\n${JSON.stringify(error)}`).not.toContain("untrusted-provider-detail");
    expect(Object.isFrozen(error)).toBe(true);
  });

  it("decodes nested EntryPoint ABI errors", () => {
    const error = new Error("opaque wrapper", {
      cause: {
        data: encodeErrorResult({
          abi: entryPoint07Abi,
          errorName: "FailedOp",
          args: [0n, "AA25 invalid account nonce"],
        }),
      },
    });
    expect(classifyUserOperationError({ stage: "estimate", error })).toMatchObject({
      code: "nonce",
      entryPointCode: "AA25",
      retryable: false,
    });
  });

  it("classifies bounded HTTP JSON bodies from caller-owned clients", () => {
    const cause = {
      body: JSON.stringify({ error: { code: -32507, message: "signature rejected" } }),
    };
    const error = classifyUserOperationError({ stage: "estimate", error: cause });
    expect(error.code).toBe("invalid-signature");
    expect(error.cause).toBe(cause);
  });

  it("captures a paymaster's HTTP 400 JSON-RPC policy refusal", async () => {
    const call = rpcOwner({
      fetch: async (request) => {
        const { id } = await request.json();
        return Response.json(
          { jsonrpc: "2.0", id, error: { code: -32501, message: "sponsorship policy denied" } },
          { status: 400 },
        );
      },
    }).pool(["https://fixture.test"], 143, ["pm_getPaymasterData"], false);
    const error = await call("pm_getPaymasterData", [], false).catch((error) => error);
    expect(error).toMatchObject({
      failure: { stage: "sponsor", code: "paymaster-policy", retryable: false },
    });
  });

  it.each(stages)("never turns %s transport failure into unsafe retry authority", (stage) => {
    const error = classifyUserOperationError({ stage, error: { code: "oaath_rpc_unavailable" } });
    expect(error).toMatchObject({
      code: "transport",
      retryable: stage === "estimate" || stage === "receipt",
    });
  });

  it("uses standardized RPC codes and a closed paymaster-policy classification", () => {
    expect(classifyUserOperationError({ stage: "estimate", error: { code: -32507 } }).code).toBe(
      "invalid-signature",
    );
    expect(classifyUserOperationError({ stage: "sponsor", error: { code: -32501 } }).code).toBe(
      "paymaster-policy",
    );
    expect(
      classifyUserOperationError({
        stage: "sponsor",
        error: { message: "sponsorship policy denied" },
      }).code,
    ).toBe("paymaster-policy");
    expect(
      classifyUserOperationError({
        stage: "estimate",
        error: { message: "sponsorship policy denied" },
      }).code,
    ).toBe("unknown");
    expect(
      classifyUserOperationError({
        stage: "sponsor",
        error: { message: "unrecognized policy prose" },
      }).code,
    ).toBe("unknown");
  });

  it("bounds cyclic/hostile causes and does not guess contradictory EntryPoint codes", () => {
    const error: { cause?: unknown; message: string } = { message: "AA21 and AA25" };
    error.cause = error;
    expect(classifyUserOperationError({ stage: "send", error }).code).toBe("unknown");
    expect(
      classifyUserOperationError({
        stage: "send",
        error: new Proxy(
          {},
          {
            getOwnPropertyDescriptor() {
              throw Error("hostile");
            },
          },
        ),
      }).code,
    ).toBe("unknown");
    expect(
      classifyUserOperationError({
        stage: "send",
        error: {
          get message() {
            throw Error("must not execute");
          },
        },
      }).code,
    ).toBe("unknown");
  });

  it.each([
    ["eth_estimateUserOperationGas", "estimate"],
    ["eth_sendUserOperation", "send"],
    ["pm_getPaymasterData", "sponsor"],
    ["eth_getUserOperationReceipt", "receipt"],
  ])("annotates the real %s RPC boundary", async (method, stage) => {
    const call = rpcOwner({
      retry: { attempts: 1 },
      fetch: async (request) => {
        const { id } = await request.json();
        return Response.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32500, message: "AA31 untrusted-provider-detail" },
        });
      },
    }).pool(["https://fixture.test"], 143, [method], false);
    const error = await call(method, [], false).catch((error) => error);
    expect(error).toMatchObject({
      code: "oaath_rpc_rejected",
      failure: { stage, code: "insufficient-funds", entryPointCode: "AA31", retryable: false },
    });
    if (!(error instanceof OaathRpcError)) throw new Error("missing RPC error");
    expect(error.cause).toMatchObject({ code: -32500 });
    expect(JSON.stringify(error)).not.toContain("untrusted-provider-detail");
  });

  it("preserves a fetch cause and never retries send", async () => {
    const cause = new Error("transport-private-detail");
    let requests = 0;
    const call = rpcOwner({
      fetch: async () => {
        requests++;
        throw cause;
      },
    }).pool(["https://fixture.test"], 143, ["eth_sendUserOperation"], false);
    const error = await call("eth_sendUserOperation", [], false).catch((error) => error);
    if (!(error instanceof OaathRpcError)) throw new Error("missing RPC error");
    expect(error.cause).toBe(cause);
    expect(error.failure).toMatchObject({ stage: "send", code: "transport", retryable: false });
    expect(requests).toBe(1);
    expect(JSON.stringify(error)).not.toContain("transport-private-detail");
  });
});

describe("UserOperation failure wire capture", () => {
  const wire = {
    version: "oaath.user-operation-failure/v1",
    stage: "send",
    code: "nonce",
    entryPointCode: "AA25",
    retryable: false,
  } as const;
  it("round trips closed diagnostics without provider causes", () => {
    const error = classifyUserOperationError({
      stage: "send",
      error: { message: "AA25 private-detail" },
    });
    expect(serializeUserOperationFailure(new Error("wrapper", { cause: error }))).toEqual(wire);
    const parsed = parseUserOperationFailure(JSON.parse(JSON.stringify(wire)));
    expect(parsed).toMatchObject({
      stage: "send",
      code: "nonce",
      entryPointCode: "AA25",
      retryable: false,
    });
    expect(parsed?.cause).toBeUndefined();
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(serializeUserOperationFailure(parsed)).toEqual(wire);
    expect(serializeUserOperationFailure({ ...error })).toBeNull();
  });
  it.each([
    { ...wire, version: "unknown" },
    { ...wire, retryable: true },
    { ...wire, code: "transport" },
    { ...wire, cause: "private-detail" },
    { ...wire, message: "private-detail" },
    { ...wire, entryPointCode: "AA99" },
    { ...wire, stage: "unknown" },
    {
      ...wire,
      get code() {
        throw Error("getter must not run");
      },
    },
  ])("rejects malformed or contradictory wire details", (value) => {
    expect(parseUserOperationFailure(value)).toBeNull();
  });
});
