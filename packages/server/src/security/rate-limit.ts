/**
 * Optional deployment-owned limiter port.
 *
 * There is no default limiter: an unset port means no limiting, and the relay
 * never invents a policy the deployment did not choose. A limiter that fails is
 * treated as `limited`, because an unreadable limiter is not permission.
 *
 * @author taek <leekt216@gmail.com>
 */

import { relayFailure } from "../relay/errors.js";

export interface RelayRateLimitInput {
  /** Stable route name, never a credential-bearing URL. */
  readonly route: string;
  readonly clientId: string | null;
}

export interface RelayRateLimiter {
  /** Resolves to `"allowed"` or `"limited"`. Anything else is `limited`. */
  check(input: RelayRateLimitInput): Promise<unknown>;
}

export async function assertWithinRateLimit(
  limiter: RelayRateLimiter | undefined,
  input: RelayRateLimitInput,
): Promise<void> {
  if (!limiter) return;
  let verdict: unknown;
  try {
    verdict = await limiter.check(input);
  } catch {
    return relayFailure("relay_rate_limited", "rate limiter is unreadable");
  }
  if (verdict !== "allowed") {
    return relayFailure("relay_rate_limited", "rate limiter rejected the call");
  }
}
