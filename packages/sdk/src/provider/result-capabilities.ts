/**
 * Closed, safely renderable wallet-call result metadata.
 *
 * These values are display-only facts. They never participate in request
 * hashing, operation preparation, signing, submission, or authority checks.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  type CaptureFailure,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "@oaath/protocol";

const SPONSOR_NAME_UTF8_BYTES = 256;
const SPONSOR_ICON_URI_BYTES = 32 * 1_024;
const SPONSOR_ICON_DECODED_BYTES = 24 * 1_024;
const RASTER_IMAGE_DATA_URI =
  /^data:image\/(?:png|jpeg|gif|webp);base64,((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/u;

export interface OaathErc7677SponsorDisplayMetadata {
  readonly name: string;
  readonly icon?: string;
}

export interface OaathWalletCallResultCapabilities {
  readonly paymasterService: Readonly<{
    readonly sponsor: Readonly<OaathErc7677SponsorDisplayMetadata>;
  }>;
}

function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function base64Sextet(value: string): number {
  const code = value.charCodeAt(0);
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26;
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52;
  return code === 0x2b ? 62 : 63;
}

function sponsorName(value: unknown, fail: CaptureFailure): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.trim() ||
    containsControlCharacter(value) ||
    new TextEncoder().encode(value).byteLength > SPONSOR_NAME_UTF8_BYTES
  ) {
    return fail("ERC-7677 sponsor name is invalid");
  }
  return value;
}

function sponsorIcon(value: unknown, fail: CaptureFailure): string {
  if (typeof value !== "string" || value.length === 0 || value.length > SPONSOR_ICON_URI_BYTES) {
    return fail("ERC-7677 sponsor icon is invalid");
  }
  const match = RASTER_IMAGE_DATA_URI.exec(value);
  const payload = match?.[1];
  if (payload === undefined || payload.length === 0) {
    return fail("ERC-7677 sponsor icon is invalid");
  }
  if (
    (payload.endsWith("==") && (base64Sextet(payload[payload.length - 3] ?? "") & 0x0f) !== 0) ||
    (payload.endsWith("=") &&
      !payload.endsWith("==") &&
      (base64Sextet(payload[payload.length - 2] ?? "") & 0x03) !== 0)
  ) {
    return fail("ERC-7677 sponsor icon is invalid");
  }
  const padding = payload.endsWith("==") ? 2 : payload.endsWith("=") ? 1 : 0;
  const decodedBytes = (payload.length / 4) * 3 - padding;
  if (decodedBytes > SPONSOR_ICON_DECODED_BYTES) {
    return fail("ERC-7677 sponsor icon is too large");
  }
  return value;
}

export function captureErc7677SponsorDisplayMetadata(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OaathErc7677SponsorDisplayMetadata> {
  const captured = captureRecord(value, "ERC-7677 sponsor", context, fail);
  const sponsor = exactCapturedRecord(
    captured,
    Object.hasOwn(captured, "icon") ? ["name", "icon"] : ["name"],
    "ERC-7677 sponsor",
    fail,
  );
  const name = sponsorName(sponsor.name, fail);
  return Object.freeze({
    name,
    ...(Object.hasOwn(sponsor, "icon") ? { icon: sponsorIcon(sponsor.icon, fail) } : {}),
  });
}

export function walletCallSponsorResultCapabilities(
  sponsor: Readonly<OaathErc7677SponsorDisplayMetadata>,
): Readonly<OaathWalletCallResultCapabilities> {
  return Object.freeze({
    paymasterService: Object.freeze({ sponsor }),
  });
}

export function captureWalletCallResultCapabilities(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OaathWalletCallResultCapabilities> {
  const capabilities = exactRecord(
    value,
    ["paymasterService"],
    "wallet call result capabilities",
    context,
    fail,
  );
  const paymasterService = exactRecord(
    capabilities.paymasterService,
    ["sponsor"],
    "wallet call paymaster result capability",
    context,
    fail,
  );
  return walletCallSponsorResultCapabilities(
    captureErc7677SponsorDisplayMetadata(paymasterService.sponsor, context, fail),
  );
}
