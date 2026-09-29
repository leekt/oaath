import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { createErc7677SponsorshipCapability } from "../provider/erc7677.js";
import { clientFail, clientFailure, exactClientRecord, mapClientFailure } from "./errors.js";
import type { OaathRegisteredPaymasterService } from "./grant-handle.js";

export interface OaathPaymasterServiceInput {
  readonly url: string;
  readonly context: unknown;
}

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
      ...(Object.hasOwn(captured, "paymasterService") ? ["paymasterService"] : []),
      ...(Object.hasOwn(captured, "feePayer") ? ["feePayer"] : []),
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
  if (Object.hasOwn(request, "feePayer") && Object.hasOwn(request, "paymasterService"))
    return fail("connected fee payer fallback cannot be combined with paymaster sponsorship");
  // An explicit lane is session sequencing; owner selection never borrows it.
  if (Object.hasOwn(request, "lane") && signer === "auto")
    return fail("an explicit lane cannot be combined with automatic signer selection");
  return Object.freeze({
    chain,
    calls: request.calls,
    ...(Object.hasOwn(request, "estimate") ? { estimate: request.estimate as boolean } : {}),
    ...(signer === undefined ? {} : { signer }),
    ...(Object.hasOwn(request, "feePayer") ? { feePayer: request.feePayer } : {}),
    ...(Object.hasOwn(request, "lane") ? { lane: request.lane } : {}),
    ...(Object.hasOwn(request, "paymasterService")
      ? { paymasterService: request.paymasterService }
      : {}),
  });
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
