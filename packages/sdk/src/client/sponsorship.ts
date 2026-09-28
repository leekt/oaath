import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { createErc7677SponsorshipCapability } from "../provider/erc7677.js";
import { clientFail, clientFailure, exactClientRecord, mapClientFailure } from "./errors.js";
import type { OaathRegisteredPaymasterService } from "./grant-handle.js";

export interface OaathPaymasterServiceInput {
  readonly url: string;
  readonly context: unknown;
}

/** One exact plain-call request shared by owner and Grant execution/review. */
export function capturePlainCalls(value: unknown, context: CaptureContext) {
  const fail = clientFailure("oaath_client_input_invalid");
  const captured = captureRecord(value, "sendCalls input", context, fail);
  const request = exactCapturedRecord(
    captured,
    [
      "chain",
      "calls",
      ...(Object.hasOwn(captured, "paymasterService") ? ["paymasterService"] : []),
    ],
    "sendCalls input",
    fail,
  );
  const chain = request.chain;
  if (typeof chain !== "number" || !Number.isSafeInteger(chain) || chain < 1)
    return fail("sendCalls chain is invalid");
  return Object.freeze({
    chain,
    calls: request.calls,
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
