import { decodeFunctionData, encodeErrorResult, toHex } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { createViemChainPorts, oaathProvider } from "../src/viem.js";
import {
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createRealm,
  createUrlRealm,
  permissionInput,
  sendCallsInput,
  TARGET,
} from "./support/browser.js";

const diagnostic = { kind: "validation_gas_likely_insufficient", verificationGasLimit: "2000000" };
const revert = (reason = "AA23 reverted", inner: `0x${string}` = "0x", index = 0n) =>
  encodeErrorResult({
    abi: entryPoint07Abi,
    errorName: "FailedOpWithRevert",
    args: [index, reason, inner],
  });

function fixture(data: unknown = revert(), onSend = false) {
  let sent = 0;
  const [ports] = createViemChainPorts(
    {
      [CHAIN_ID]: {
        publicRpcUrls: ["https://public.test"],
        bundlerUrl: "https://bundler.test",
        paymasterUrl: "https://paymaster.test",
      },
    },
    {
      fetch: async (request) => {
        const { id, method, params } = await request.json();
        let result: unknown;
        if (method === "eth_chainId") result = toHex(CHAIN_ID);
        else if (method === "eth_call") {
          const decoded = decodeFunctionData({ abi: entryPoint07Abi, data: params[0].data });
          if (decoded.functionName !== "getNonce") throw new Error("unexpected read");
          result = toHex(decoded.args[1] << 64n, { size: 32 });
        } else if (method === "eth_getBlockByNumber")
          result = { baseFeePerGas: "0x3b9aca00", number: "0x1", hash: `0x${"11".repeat(32)}` };
        else if (method === "eth_maxPriorityFeePerGas") result = "0x3b9aca00";
        else if (method === "eth_sendUserOperation" || method === "eth_estimateUserOperationGas") {
          if (method === "eth_sendUserOperation") sent++;
          return Response.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32500, message: "AA23 provider-private-material", data },
          });
        } else if (method === "pm_getPaymasterStubData")
          result = {
            paymaster: "0x3333333333333333333333333333333333333333",
            paymasterData: "0x01",
            paymasterPostOpGasLimit: "0x64",
          };
        else throw new Error("unexpected method");
        return Response.json({ jsonrpc: "2.0", id, result });
      },
    },
  );
  const base = createChainFixture();
  const chain = {
    ...base,
    capability: {
      ...base.capability,
      gas: { enableVerificationGasFloor: 2_000_000n },
      quote: onSend ? base.capability.quote : ports!.quote,
      submission: onSend ? ports!.submission : base.capability.submission,
      paymasterService: ports!.paymasterService,
    },
  };
  return { chain, base, sent: () => sent };
}

describe("AA23 empty validation revert diagnostic", () => {
  it.each([
    { name: "direct", create: createRealm },
    { name: "relay", create: createUrlRealm },
  ])("reaches the $name Grant caller before signing", async ({ create }) => {
    const { chain, base } = fixture();
    const realm = create({ chain });
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const error = await grant.sendCalls(sendCallsInput()).catch((error: unknown) => error);
      expect(error).toMatchObject({
        code: "oaath_client_preparation_failed",
        diagnostic,
        message: "likely validation out-of-gas (verificationGasLimit=2000000)",
      });
      expect(JSON.stringify(error).includes("provider-private-material")).toBe(false);
      expect(base.signatures.length).toBe(0);
      expect(base.sends.length).toBe(0);
    } finally {
      await realm.oaath.close();
    }
  });

  it.each([
    revert("AA24 signature error"),
    revert("AA23 reverted", "0x1234"),
    revert("AA23 reverted", "0x", 1n),
    "0x",
    { reason: "AA23 reverted", data: "0x" },
  ])("does not infer gas exhaustion from missing or different evidence", async (data) => {
    const { chain } = fixture(data);
    const realm = createRealm({ chain });
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const error = (await grant.sendCalls(sendCallsInput()).catch((error: unknown) => error)) as {
        diagnostic?: unknown;
      };
      expect(error.diagnostic ?? null).toBeNull();
    } finally {
      await realm.oaath.close();
    }
  });

  it("reports a send diagnostic without resubmitting or releasing its lane", async () => {
    const { chain, sent } = fixture(revert(), true);
    const realm = createRealm({ chain });
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const operation = await grant.sendCalls(sendCallsInput());
      expect(operation.outcome).toMatchObject({ status: "pending", diagnostic });
      expect(await operation.wait({ attempts: 1 })).toMatchObject({
        status: "pending",
        diagnostic,
      });
      await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
        code: "oaath_client_state_conflict",
      });
      expect(sent()).toBe(1);
    } finally {
      await realm.oaath.close();
    }
  });

  it("preserves the diagnostic through sponsorship and the provider's fixed error boundary", async () => {
    const { chain, base } = fixture();
    const realm = createRealm({ chain });
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      const provider = oaathProvider({ grant, chain: CHAIN_ID });
      const error = await provider
        .request({
          method: "wallet_sendCalls",
          params: [
            {
              version: "2.0.0",
              id: "aa23",
              from: await grant.account(CHAIN_ID),
              chainId: toHex(CHAIN_ID),
              atomicRequired: true,
              calls: [{ to: TARGET, data: CALL_DATA }],
              capabilities: { paymasterService: { url: "https://paymaster.test", context: {} } },
            },
          ],
        })
        .catch((error: unknown) => error);
      expect(error).toMatchObject({
        code: -32603,
        message: "Internal error",
        data: { diagnostic },
      });
      expect(base.signatures.length).toBe(0);
    } finally {
      await realm.oaath.close();
    }
  });
});
