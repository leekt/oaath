/*
 * Example-owned pairing for the owner-phone demo. These helpers expose the
 * current in-memory pairing secret to the loopback browser and reserve it
 * for one enrollment.
 *
 * @author taek <leekt216@gmail.com>
 */

export const DEMO_PAIRING_SECRET_VERSION = "oaath.demo-pairing-secret/v1";

/** Reserves the example's pairing code synchronously before account reads. */
export class OneShotPairing {
  #hash;
  #expiresAt;
  #consumed = false;

  constructor({ hash, expiresAt }) {
    this.#hash = hash;
    this.#expiresAt = expiresAt;
  }

  available(now) {
    return !this.#consumed && now < this.#expiresAt;
  }

  reserve({ hash, now }) {
    if (!this.available(now) || hash !== this.#hash) throw new Error("pairing_invalid");
    this.#consumed = true;
  }
}

const sendJson = (outgoing, status, body) => {
  outgoing.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  outgoing.end(JSON.stringify(body));
};

const refuse = (outgoing, status, code) => sendJson(outgoing, status, { error: { code } });

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
  if (!(await pairingAvailable())) {
    refuse(outgoing, 410, "pairing_secret_unavailable");
    return true;
  }
  const qrDataUrl = await renderQr(pairingLink);
  if (!(await pairingAvailable())) {
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
