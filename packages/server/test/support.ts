/**
 * Shared relay test harness: deterministic clock, deployment authentication,
 * reversible KMS, and request/response helpers.
 *
 * @author taek <leekt216@gmail.com>
 */

import { expect } from "vitest";
import { sha256Base64Url } from "../src/authorization/challenge.js";
import type { RelayClock } from "../src/clock.js";
import { RELAY_ERROR_STATUS, type RelayErrorCode } from "../src/relay/errors.js";
import { createRelayHandler, type RelayHandlerOptions } from "../src/relay/handler.js";
import type { RelayAuthentication, RelayCaller } from "../src/security/authentication.js";
import type { RelayKms } from "../src/security/kms.js";
import type { RelayStore } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";

export const ORIGIN = "https://relay.example";
export const REDIRECT_URI = "https://app.example/callback";
/** 43 unreserved characters: the RFC 7636 minimum. */
export const CODE_VERIFIER = "u9Xq2Tb7yZ0aVc4Nk1Lm6Pr8Sd3Wf5Hg7Jt9Bn2Qx0z";

export const CLIENT_TOKEN = "client-token";
export const OWNER_TOKEN = "owner-token";
export const OTHER_CLIENT_TOKEN = "other-client-token";
export const OTHER_OWNER_TOKEN = "other-owner-token";

export const CALLERS: ReadonlyMap<string, RelayCaller> = new Map([
  [
    CLIENT_TOKEN,
    {
      role: "client",
      clientId: "client-a",
      subject: "subject-1",
      redirectUris: [REDIRECT_URI],
    } satisfies RelayCaller,
  ],
  [
    OTHER_CLIENT_TOKEN,
    {
      role: "client",
      clientId: "client-b",
      subject: "subject-1",
      redirectUris: [REDIRECT_URI],
    } satisfies RelayCaller,
  ],
  [
    OWNER_TOKEN,
    {
      role: "owner",
      clientId: "owner-console",
      subject: "subject-1",
      redirectUris: [],
    } satisfies RelayCaller,
  ],
  [
    OTHER_OWNER_TOKEN,
    {
      role: "owner",
      clientId: "owner-console",
      subject: "subject-2",
      redirectUris: [],
    } satisfies RelayCaller,
  ],
]);

export interface TestClock extends RelayClock {
  advance(milliseconds: number): void;
}

export function createTestClock(start = 1_700_000_000_000): TestClock {
  let current = start;
  return {
    now: () => current,
    advance: (milliseconds) => {
      current += milliseconds;
    },
  };
}

export function createTestAuthentication(): RelayAuthentication {
  return {
    async authenticate(request: Request) {
      const header = request.headers.get("authorization") ?? "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
      return CALLERS.get(token) ?? null;
    },
  };
}

const KMS_PREFIX = "oaath-test-kms:v1:";

/** Deterministic and reversible, so a "restart" can still open earlier references. */
export function createTestKms(): RelayKms {
  return {
    async encrypt(plaintext: string) {
      return `${KMS_PREFIX}${btoa(plaintext)}`;
    },
    async decrypt(ciphertextRef: string) {
      if (!ciphertextRef.startsWith(KMS_PREFIX)) throw new Error("unknown ciphertext reference");
      return atob(ciphertextRef.slice(KMS_PREFIX.length));
    },
  };
}

export function codeChallenge(): Promise<string> {
  return sha256Base64Url(CODE_VERIFIER);
}

export interface Harness {
  readonly handler: (request: Request) => Promise<Response>;
  readonly store: RelayStore;
  readonly clock: TestClock;
  readonly kms: RelayKms;
}

export function createHarness(
  overrides: Partial<RelayHandlerOptions> = {},
  store: RelayStore = createMemoryRelayStore(),
  clock: TestClock = createTestClock(),
): Harness {
  const kms = overrides.kms ?? createTestKms();
  return {
    handler: createRelayHandler({
      store,
      authentication: createTestAuthentication(),
      clock,
      ...overrides,
      kms,
    }),
    store,
    clock,
    kms,
  };
}

export function post(path: string, token: string | null, body?: unknown): Request {
  const headers = new Headers();
  if (token !== null) headers.set("authorization", `Bearer ${token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

export function get(path: string, token: string | null): Request {
  const headers = new Headers();
  if (token !== null) headers.set("authorization", `Bearer ${token}`);
  return new Request(`${ORIGIN}${path}`, { method: "GET", headers });
}

/** Asserts a failure by code and status only; a response never carries text. */
export async function expectFailure(response: Response, code: RelayErrorCode): Promise<void> {
  expect(response.status).toBe(RELAY_ERROR_STATUS[code]);
  expect(await response.json()).toEqual({ error: { code } });
}

export async function expectOk<Value>(response: Response, status: number): Promise<Value> {
  expect(response.status).toBe(status);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return (await response.json()) as Value;
}

export interface CreatedRequest {
  readonly requestId: string;
  readonly expiresAt: number;
}

export interface ApprovedDecision {
  readonly outcome: "approved";
  readonly decidedAt: number;
  readonly code: string;
  readonly artifactId: string;
  readonly redirectUri: string;
  readonly codeExpiresAt: number;
}

export async function createRequest(harness: Harness): Promise<CreatedRequest> {
  const response = await harness.handler(
    post("/authorization/requests", CLIENT_TOKEN, {
      redirectUri: REDIRECT_URI,
      codeChallenge: await codeChallenge(),
      requestedScope: '{"chainScope":"all"}',
    }),
  );
  return expectOk<CreatedRequest>(response, 201);
}

export async function approve(
  harness: Harness,
  requestId: string,
  artifact = '{"grant":"approved"}',
): Promise<ApprovedDecision> {
  const response = await harness.handler(
    post(`/authorization/requests/${requestId}/decision`, OWNER_TOKEN, {
      outcome: "approved",
      artifact,
    }),
  );
  return expectOk<ApprovedDecision>(response, 200);
}

export function consume(harness: Harness, code: string, token = CLIENT_TOKEN): Promise<Response> {
  return harness.handler(
    post("/authorization/codes/consume", token, {
      code,
      codeVerifier: CODE_VERIFIER,
      redirectUri: REDIRECT_URI,
    }),
  );
}

export function claim(
  harness: Harness,
  artifactId: string,
  token = CLIENT_TOKEN,
): Promise<Response> {
  return harness.handler(post(`/authorization/artifacts/${artifactId}/claim`, token));
}
