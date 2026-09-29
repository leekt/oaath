import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { createErc7677SponsorshipCapability } from "../provider/erc7677.js";
import type { OaathConnectedEoaPayer } from "./connected-eoa.js";
import { clientFail, clientFailure, exactClientRecord, mapClientFailure } from "./errors.js";
import type { OaathRegisteredPaymasterService } from "./grant-handle.js";

/** An ERC-7677 paymaster service registered on the chain capability sponsors gas. */
export interface OaathPaymasterServicePayer {
  readonly kind: "paymaster-service";
  readonly url: string;
  readonly context: unknown;
}

/**
 * Who pays gas for one call. Omit it and the account pays through the chain's
 * configured submission routes. `connected-eoa` pays only on the fallback
 * route, after a conclusive bundler rejection of the same signed operation.
 */
export type OaathPayer = OaathPaymasterServicePayer | OaathConnectedEoaPayer;

/** One exact plain-call request shared by owner and Grant execution/review. */
export function capturePlainCalls(
  value: unknown,
  context: CaptureContext,
  allowSigner = false,
  review = false,
  allowLane = false,
) {
  const fail = clientFailure("oaath_client_input_invalid");
  const captured = captureRecord(value, "sendCalls input", context, fail);
  const request = exactCapturedRecord(
    captured,
    [
      "chain",
      "calls",
      ...(allowSigner && Object.hasOwn(captured, "signer") ? ["signer"] : []),
      ...(Object.hasOwn(captured, "payer") ? ["payer"] : []),
      ...(review && Object.hasOwn(captured, "estimate") ? ["estimate"] : []),
      ...(allowLane && Object.hasOwn(captured, "lane") ? ["lane"] : []),
    ],
    "sendCalls input",
    fail,
  );
  if (Object.hasOwn(request, "signer") && request.signer !== "auto" && request.signer !== "session")
    return fail("Grant signer must be auto or session");
  const signer = request.signer as "auto" | "session" | undefined;
  const chain = request.chain;
  if (Object.hasOwn(request, "estimate") && typeof request.estimate !== "boolean")
    return fail("review estimate must be a boolean");
  if (typeof chain !== "number" || !Number.isSafeInteger(chain) || chain < 1)
    return fail("sendCalls chain is invalid");
  const payer = Object.hasOwn(request, "payer") ? capturePayer(request.payer, context) : null;
  // An explicit lane is session sequencing; owner selection never borrows it.
  if (Object.hasOwn(request, "lane") && signer === "auto")
    return fail("an explicit lane cannot be combined with automatic signer selection");
  return Object.freeze({
    chain,
    calls: request.calls,
    ...(Object.hasOwn(request, "estimate") ? { estimate: request.estimate as boolean } : {}),
    ...(signer === undefined ? {} : { signer }),
    ...(payer?.kind === "connected-eoa" ? { feePayer: payer.feePayer } : {}),
    ...(Object.hasOwn(request, "lane") ? { lane: request.lane } : {}),
    ...(payer?.kind === "paymaster-service" ? { paymasterService: payer.paymasterService } : {}),
  });
}

/** Splits the one payer setting into the exact input its owner captures. */
function capturePayer(value: unknown, context: CaptureContext) {
  const fail = clientFailure("oaath_client_input_invalid");
  const payer = captureRecord(value, "payer", context, fail);
  if (payer.kind === "connected-eoa") {
    const { kind, wallet } = exactCapturedRecord(payer, ["kind", "wallet"], "payer", fail);
    return { kind: "connected-eoa" as const, feePayer: { kind, wallet } };
  }
  if (payer.kind === "paymaster-service") {
    const exact = exactCapturedRecord(payer, ["kind", "url", "context"], "payer", fail);
    return {
      kind: "paymaster-service" as const,
      paymasterService: { url: exact.url, context: exact.context },
    };
  }
  return fail("payer kind is unsupported");
}

/** Selects only the registered capability; construction performs no request. */
export function capturePaymasterService(
  value: unknown,
  registered: Readonly<OaathRegisteredPaymasterService> | null,
  context: CaptureContext,
) {
  const requested = exactClientRecord(value, ["url", "context"], "paymaster service", context);
  if (typeof requested.url !== "string")
    return clientFail("oaath_client_input_invalid", "paymaster URL is invalid");
  if (registered === null || requested.url !== registered.url)
    return clientFail(
      "oaath_client_capability_invalid",
      "paymaster service is not registered",
      "erc7677_service_unregistered",
    );
  try {
    return createErc7677SponsorshipCapability({
      requested: { url: requested.url, context: requested.context },
      service: { url: registered.url, request: registered.request },
      estimator: { estimate: registered.estimate },
    });
  } catch (error) {
    return mapClientFailure(error, "paymaster service could not be selected");
  }
}
