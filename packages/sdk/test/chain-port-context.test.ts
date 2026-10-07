import { describe, expect, it } from "vitest";
import type { OaathChainCapability, OaathQuoteRequest } from "../src/advanced.js";
import { oaathProvider } from "../src/cetane.js";
import { parsePreparedUserOperation } from "../src/kernel.js";
import { encodeKernelV4NonceKey } from "../src/kernel-v4.js";
import {
  ACCOUNT,
  CALL_DATA,
  CHAIN_ID,
  createChainFixture,
  createRealm,
  createUrlRealm,
  permissionInput,
  SESSION_PUBLIC_KEY,
  sendCallsInput,
  signPreparedDigest,
  TARGET,
} from "./support/browser.js";

function capturedChain() {
  const base = createChainFixture();
  const quotes: OaathQuoteRequest[] = [];
  const usage: Parameters<NonNullable<OaathChainCapability["usage"]>>[0][] = [];
  const chain = {
    ...base,
    capability: {
      ...base.capability,
      reads: {
        async read(request: Parameters<OaathChainCapability["reads"]["read"]>[0]) {
          if (request.type === "code" && request.address === ACCOUNT && base.sends.length > 0) {
            return "0x01";
          }
          return base.capability.reads.read(request);
        },
      },
      async quote(request: OaathQuoteRequest) {
        quotes.push(request);
        return base.capability.quote(request);
      },
      async usage(request: Parameters<NonNullable<OaathChainCapability["usage"]>>[0]) {
        usage.push(request);
        return base.capability.usage!(request);
      },
    },
  };
  return { base, chain, quotes, usage };
}

describe("runtime-owned chain port context", () => {
  it.each([
    { mode: "direct", create: createRealm },
    { mode: "relay", create: createUrlRealm },
  ])(
    "supplies usage identity and first-enable / installed simulation through $mode ports",
    async ({ create }) => {
      const { chain, base, quotes, usage } = capturedChain();
      const realm = create({ chain });
      try {
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        const first = await grant.sendCalls(sendCallsInput());
        expect((await first.wait()).status).toBe("finalized");
        const second = await grant.sendCalls(sendCallsInput());
        expect((await second.wait()).status).toBe("finalized");
        expect(quotes).toHaveLength(2);
        for (const [index, request] of quotes.entries()) {
          // Check presence before inspecting sensitive simulation bytes so a failed
          // expectation never dumps an approval envelope or signed operation.
          expect(request.simulation !== undefined).toBe(true);
          expect(request.purpose).toBe("estimate");
          const prepared = parsePreparedUserOperation(request.simulation.prepared);
          const submitted = base.sends[index]!;
          expect(prepared.userOperation.sender).toBe(ACCOUNT);
          expect(prepared.userOperation.callData === submitted.userOperation.callData).toBe(true);
          expect(prepared.userOperation.factory === null).toBe(index === 1);
          expect(prepared.userOperation.nonce).toBe(
            (
              BigInt(
                encodeKernelV4NonceKey({
                  mode: request.mode,
                  validation: request.validation,
                  nonceKey: "0",
                }),
              ) << 64n
            ).toString(),
          );
          expect(request.simulation.signature !== base.signatures[index]).toBe(true);
          expect(usage[index]).toMatchObject({
            account: ACCOUNT,
            chainId: CHAIN_ID,
            grantId: prepared.grantId,
            permissionId:
              request.validation.kind === "permission" ? request.validation.permissionId : null,
            maximumOperations: "10",
          });
        }
        // The first signature includes the retained owner approval and install
        // packages, while the next uses only the standard permission envelope.
        expect(
          quotes[0]!.simulation.signature.length > quotes[1]!.simulation.signature.length,
        ).toBe(true);
      } finally {
        await realm.oaath.close();
      }
    },
  );

  it.each([false, true])(
    "supplies external-key simulation and retains final gas on revalidation (sponsored=%s)",
    async (sponsored) => {
      const { chain, base, quotes } = capturedChain();
      const url = "https://issuer.example/paymaster";
      const sponsorship: OaathChainCapability["sponsorship"] = sponsored
        ? {
            kind: "erc7677",
            url,
            async request(request) {
              return {
                paymaster: "0x3333333333333333333333333333333333333333",
                paymasterData: "0x01",
                ...(request.method === "pm_getPaymasterStubData"
                  ? { paymasterPostOpGasLimit: "0x64" }
                  : {}),
              };
            },
            async estimate() {
              return {
                callGasLimit: "110000",
                verificationGasLimit: "210000",
                preVerificationGas: "50000",
                paymasterVerificationGasLimit: "100000",
              };
            },
          }
        : undefined;
      const realm = createRealm({
        chain: {
          ...chain,
          capability: { ...chain.capability, ...(sponsorship ? { sponsorship } : {}) },
        },
      });
      try {
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        const provider = oaathProvider({ grant, chain: CHAIN_ID });
        const response = (await provider.request({
          method: "wallet_prepareCalls",
          params: [
            {
              version: "1",
              chainId: `0x${CHAIN_ID.toString(16)}`,
              from: ACCOUNT,
              calls: [{ to: TARGET, value: "0x0", data: CALL_DATA }],
              key: { type: "secp256k1", publicKey: SESSION_PUBLIC_KEY, prehash: false },
              ...(sponsored ? { capabilities: { paymasterService: { url, context: {} } } } : {}),
            },
          ],
        })) as {
          digest: `0x${string}`;
          version: string;
          chainId: string;
          capabilities: unknown;
          context: unknown;
          key: unknown;
        };
        expect(quotes).toHaveLength(1);
        expect(quotes[0]!.simulation !== undefined).toBe(true);
        expect(quotes[0]!.simulation.prepared.userOperation.factory !== null).toBe(true);
        expect(quotes[0]!.simulation.signature.length > 132).toBe(true);
        expect(base.signatures.length).toBe(0);
        expect(base.sends.length).toBe(0);
        expect(quotes[0]!.purpose).toBe(sponsored ? "sponsorship" : "estimate");
        await provider.request({
          method: "wallet_sendPreparedCalls",
          params: [
            {
              version: response.version,
              chainId: response.chainId,
              capabilities: response.capabilities,
              context: response.context,
              key: response.key,
              signature: await signPreparedDigest(response.digest),
            },
          ],
        });
        expect(quotes).toHaveLength(2);
        expect(quotes[1]!.purpose).toBe("revalidate");
        const simulated = quotes[1]!.simulation.prepared.userOperation;
        const submitted = base.sends[0]!.userOperation;
        expect(simulated.maxFeePerGas).toBe(submitted.maxFeePerGas);
        expect(simulated.callGasLimit).toBe(submitted.callGasLimit);
        expect(simulated.verificationGasLimit).toBe(submitted.verificationGasLimit);
        expect(JSON.stringify(simulated.paymaster) === JSON.stringify(submitted.paymaster)).toBe(
          true,
        );
      } finally {
        await realm.oaath.close();
      }
    },
  );

  it("still refuses unavailable usage before quote, signing or submission", async () => {
    const base = createChainFixture();
    let usageHadIdentity = false;
    const realm = createRealm({
      chain: {
        ...base,
        capability: {
          ...base.capability,
          async usage(request) {
            usageHadIdentity =
              request.account === ACCOUNT && /^0x[0-9a-f]{8}$/.test(request.permissionId);
            throw new Error("unavailable");
          },
        },
      },
    });
    try {
      const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
      await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
        code: "oaath_client_scope_denied",
      });
      expect(usageHadIdentity).toBe(true);
      expect(base.quotes).toBe(0);
      expect(base.signatures.length).toBe(0);
      expect(base.sends.length).toBe(0);
    } finally {
      await realm.oaath.close();
    }
  });
});
