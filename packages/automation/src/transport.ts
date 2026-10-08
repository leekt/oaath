/**
 * The one HTTP transport: bearer token, JSON, no redirects, bounded time, and
 * no retries. A request whose reply is lost fails as `request_outcome_unknown`;
 * it never sends again.
 *
 * @author taek <leekt216@gmail.com>
 */
import { AutomationError } from "./error.js";

export interface AutomationClientOptions {
  /** The automation service's base URL, e.g. `https://automation.example.com`. */
  readonly baseUrl: string;
  /** An application credential (server) or a session token (browser). */
  readonly token: string | (() => string | Promise<string>);
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}

export type AutomationRequest = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function createTransport(options: AutomationClientOptions): AutomationRequest {
  let url: URL;
  try {
    url = new URL(options.baseUrl);
  } catch {
    throw new AutomationError("base_url_invalid", 0);
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new AutomationError("base_url_invalid", 0);
  const base = url.href.replace(/\/$/u, "");
  const fetcher = options.fetch ?? globalThis.fetch;
  return async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = typeof options.token === "function" ? await options.token() : options.token;
    let response: Response;
    try {
      response = await fetcher(base + path, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
        redirect: "error",
      });
    } catch {
      throw new AutomationError("request_outcome_unknown", 0);
    }
    const value: unknown = await response.json().catch(() => {
      throw new AutomationError("response_unreadable", response.status);
    });
    if (!response.ok) {
      const code = (value as { error?: { code?: unknown } } | null)?.error?.code;
      throw new AutomationError(
        typeof code === "string" && /^[a-z0-9_]{1,100}$/u.test(code) ? code : "request_failed",
        response.status,
      );
    }
    if (!value || typeof value !== "object")
      throw new AutomationError("response_invalid", response.status);
    return value as T;
  };
}
