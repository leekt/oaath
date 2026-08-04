/*
 * Example-owned HTTP projections for the owner-phone demo. These helpers do
 * not create or decide authorization requests: they only expose the current
 * in-memory pairing secret to the loopback browser and the pending request
 * summaries to the exact active paired phone.
 *
 * @author taek <leekt216@gmail.com>
 */

export const DEMO_INBOX_VERSION = "oaath.demo-inbox/v1";
export const DEMO_INBOX_LIMIT = 20;
export const DEMO_PAIRING_SECRET_VERSION = "oaath.demo-pairing-secret/v1";

const sendJson = (outgoing, status, body) => {
  outgoing.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  outgoing.end(JSON.stringify(body));
};

const refuse = (outgoing, status, code) => sendJson(outgoing, status, { error: { code } });

const bearer = (header) =>
  typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";

export function isLoopbackAddress(address) {
  if (typeof address !== "string") return false;
  if (address === "::1") return true;
  const normalized = address.startsWith("::ffff:") ? address.slice(7) : address;
  const parts = normalized.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((part) => /^(?:0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255)
  );
}

export function compareOperationIds(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function pendingInbox(records, now, limit = DEMO_INBOX_LIMIT) {
  return [...records.values()]
    .filter(
      (record) =>
        record.inboxState === "pending" &&
        record.inboxSummary !== undefined &&
        record.inboxSummary.expiresAt > now,
    )
    .map((record) => record.inboxSummary)
    .sort(
      (left, right) =>
        left.expiresAt - right.expiresAt ||
        compareOperationIds(left.operationId, right.operationId),
    )
    .slice(0, limit);
}

export function markInboxTerminal(records, operationId) {
  const record = records.get(operationId);
  if (record?.inboxState === "pending") record.inboxState = "terminal";
}

/** GET /demo/inbox. Returns true only when this helper owns the route. */
export function serveDemoInbox({ incoming, outgoing, pathname, activeDevice, records, now }) {
  if (pathname !== "/demo/inbox") return false;
  if (incoming.method !== "GET") {
    refuse(outgoing, 405, "demo_method_not_allowed");
    return true;
  }
  const credential = bearer(incoming.headers.authorization);
  if (activeDevice === null || credential === "" || credential !== activeDevice.credential) {
    refuse(outgoing, 401, "device_unauthorized");
    return true;
  }
  // Sorted insertion order is the canonical wire order accepted by the Swift
  // codec. Listing reads only the existing record summaries.
  const requests = pendingInbox(records, now()).map((item) => ({
    displayPayload: item.displayPayload,
    expiresAt: item.expiresAt,
    operationId: item.operationId,
  }));
  sendJson(outgoing, 200, { requests, version: DEMO_INBOX_VERSION });
  return true;
}

/**
 * POST /demo/pairing-secret. The socket address and fixed origin allowlist are
 * independent checks; Host and forwarding headers never authorize disclosure.
 */
export async function servePairingSecret({
  incoming,
  outgoing,
  pathname,
  allowedOrigins,
  pairingAvailable,
  pairingLink,
  expiresAt,
  renderQr,
}) {
  if (pathname !== "/demo/pairing-secret") return false;
  if (incoming.method !== "POST") {
    refuse(outgoing, 405, "demo_method_not_allowed");
    return true;
  }
  if (
    !isLoopbackAddress(incoming.socket.remoteAddress) ||
    !allowedOrigins.has(incoming.headers.origin ?? "")
  ) {
    refuse(outgoing, 403, "pairing_loopback_required");
    return true;
  }
  if (!pairingAvailable()) {
    refuse(outgoing, 410, "pairing_secret_unavailable");
    return true;
  }
  const qrDataUrl = await renderQr(pairingLink);
  if (!pairingAvailable()) {
    refuse(outgoing, 410, "pairing_secret_unavailable");
    return true;
  }
  if (typeof qrDataUrl !== "string" || !qrDataUrl.startsWith("data:image/png;base64,")) {
    refuse(outgoing, 500, "pairing_qr_unavailable");
    return true;
  }
  sendJson(outgoing, 200, {
    expiresAt,
    pairingLink,
    qrDataUrl,
    version: DEMO_PAIRING_SECRET_VERSION,
  });
  return true;
}
