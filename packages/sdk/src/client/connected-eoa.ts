/** One optional connected-wallet send after a conclusive refusal of the exact signed operation. */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import { toHex } from "cetane/utils";
import { OaathRpcError } from "../cetane/rpc.js";
import type { OperationSubmissionSession } from "../operation-runner.js";
import { routingAddress } from "../routing/capabilities.js";
import { classifyBundlerAcceptance } from "../routing/erc4337/bundler.js";
import { encodeHandleOps } from "../routing/erc4337/handle-ops.js";
import { clientFail, clientFailure, exactClientRecord } from "./errors.js";
import type { OaathSubmissionRequest } from "./grant-handle.js";

type ConnectedEoaRpcRequest =
  | { method: "eth_accounts" | "eth_chainId" }
  | {
      method: "eth_sendTransaction";
      params: [
        {
          from: `0x${string}`;
          to: `0x${string}`;
          data: `0x${string}`;
          value: `0x${string}`;
          chainId: `0x${string}`;
        },
      ];
    };

/** A connected wallet that sends `handleOps` after a conclusive bundler rejection. */
export interface OaathConnectedEoaPayer {
  readonly kind: "connected-eoa";
  readonly wallet: {
    readonly account?: Readonly<{ address: `0x${string}`; type?: string }>;
    readonly signer?: Readonly<{ sign: (request: { hash: `0x${string}` }) => unknown }>;
    readonly request: (
      request: ConnectedEoaRpcRequest,
      options?: { retryCount: 0 },
    ) => Promise<unknown>;
    readonly sendTransaction?: (
      input: Readonly<{
        to: `0x${string}`;
        data: `0x${string}`;
        value: bigint;
      }>,
    ) => Promise<unknown>;
  };
}
export interface OaathConnectedEoaFallbackReview {
  /** Opaque route identity of the fallback transaction. */
  readonly route: string;
  readonly feePayer: `0x${string}`;
  readonly condition: "conclusive_bundler_rejection";
}
export interface ConnectedEoa {
  readonly address: `0x${string}`;
  readonly request: OaathConnectedEoaPayer["wallet"]["request"];
  readonly localSend:
    | ((input: { to: `0x${string}`; data: `0x${string}`; value: bigint }) => Promise<unknown>)
    | null;
}

/** Captures a borrowed wallet capability without contacting or prompting it. */
export function captureConnectedEoa(
  value: unknown,
  context: CaptureContext,
): Readonly<ConnectedEoa> {
  const fail = clientFailure("oaath_client_input_invalid");
  const input = exactClientRecord(value, ["kind", "wallet"], "connected fee payer", context);
  if (input.kind !== "connected-eoa") return fail("fee payer kind is unsupported");
  const wallet = captureRecord(input.wallet, "connected fee payer wallet", context, fail);
  const account = captureRecord(wallet.account, "connected fee payer account", context, fail);
  const address = routingAddress(account.address, "connected fee payer address", fail);
  if (typeof wallet.request !== "function") return fail("connected fee payer request is missing");
  const local = account.type === "local" || wallet.signer !== undefined;
  if (wallet.signer !== undefined) {
    const signer = captureRecord(wallet.signer, "connected fee payer signer", context, fail);
    if (typeof signer.sign !== "function") return fail("local fee payer signer is missing");
  }
  if (local && typeof wallet.sendTransaction !== "function")
    return fail("local fee payer sendTransaction is missing");
  const send = wallet.sendTransaction as NonNullable<
    OaathConnectedEoaPayer["wallet"]["sendTransaction"]
  >;
  return Object.freeze({
    address,
    request: wallet.request as OaathConnectedEoaPayer["wallet"]["request"],
    localSend: local
      ? (call: { to: `0x${string}`; data: `0x${string}`; value: bigint }) => send(call)
      : null,
  });
}

export function connectedEoaReview(
  payer: Readonly<ConnectedEoa> | null,
): Readonly<OaathConnectedEoaFallbackReview> | null {
  return payer === null
    ? null
    : Object.freeze({
        route: "erc4337-handleops",
        feePayer: payer.address,
        condition: "conclusive_bundler_rejection",
      });
}

export function withConnectedEoaFallback(
  session: Readonly<OperationSubmissionSession>,
  input: Readonly<OaathSubmissionRequest>,
  payer: Readonly<ConnectedEoa> | null,
): Readonly<OperationSubmissionSession> {
  if (payer === null) return session;
  const wallet = payer;
  let closed = false;
  let sent: Promise<unknown> | undefined;
  async function send(): Promise<unknown> {
    try {
      return await session.submit();
    } catch (error) {
      if (
        closed ||
        input.route !== "erc4337-bundler" ||
        !(error instanceof OaathRpcError) ||
        error.code !== "oaath_rpc_rejected" ||
        classifyBundlerAcceptance({ outcome: "rejected", code: error.rpcCode }) !== "unsupported"
      )
        throw error;
    }
    // Packing revalidates the hash and rejects sponsorship. Never re-prepare or sign.
    const call = encodeHandleOps({
      prepared: input.prepared,
      signature: input.signature,
      beneficiary: wallet.address,
    });
    let chain: unknown;
    let accounts: unknown;
    try {
      [chain, accounts] = await Promise.all([
        wallet.request({ method: "eth_chainId" }, { retryCount: 0 }),
        wallet.localSend === null
          ? wallet.request({ method: "eth_accounts" }, { retryCount: 0 })
          : Promise.resolve([wallet.address]),
      ]);
    } catch {
      return clientFail("oaath_client_capability_invalid", "connected fee payer could not be read");
    }
    if (closed) return clientFail("oaath_client_closed", "submission session is closed");
    if (
      chain !== toHex(input.prepared.chainId) ||
      !Array.isArray(accounts) ||
      !accounts.some(
        (account) => typeof account === "string" && account.toLowerCase() === wallet.address,
      )
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "connected fee payer account or chain changed",
      );
    }
    let hash: unknown;
    try {
      hash =
        wallet.localSend !== null
          ? await wallet.localSend({ to: call.entryPoint, data: call.data, value: 0n })
          : await wallet.request(
              {
                method: "eth_sendTransaction",
                params: [
                  {
                    from: wallet.address,
                    to: call.entryPoint,
                    data: call.data,
                    value: "0x0",
                    chainId: toHex(call.chainId),
                  },
                ],
              },
              { retryCount: 0 },
            );
    } catch {
      return clientFail(
        "oaath_client_capability_invalid",
        "connected fee payer submission is uncertain",
      );
    }
    if (typeof hash !== "string" || !/^0x[0-9a-f]{64}$/iu.test(hash))
      return clientFail(
        "oaath_client_capability_invalid",
        "connected fee payer returned an invalid transaction hash",
      );
    return Object.freeze({
      userOperationHash: call.userOperationHash,
      submission: Object.freeze({
        route: "erc4337-handleops",
        transactionHash: hash.toLowerCase() as `0x${string}`,
      }),
    });
  }
  return Object.freeze({
    submit() {
      if (closed) return Promise.reject(new Error("submission session is closed"));
      sent ??= send();
      return sent;
    },
    async close() {
      closed = true;
      await session.close();
    },
  });
}
