/**
 * `@oaath/automation/server` — the application backend's client. The
 * application credential belongs only here; derive `userId` and `account`
 * from your own authenticated session, never from browser input.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { Address } from "./definition.js";
import type { KeyScope, Session } from "./index.js";
import { type AutomationClientOptions, createTransport } from "./transport.js";

export function createAutomationServer(options: AutomationClientOptions) {
  const request = createTransport(options);
  return Object.freeze({
    /** One hour, bound to this application, user and account. */
    createSession: (identity: Readonly<{ userId: string; account: Address }>) =>
      request<Session>("POST", "/v1/sessions", identity),
    /** Session-key custody for new plans: one key per user (default) or per application. */
    configureSigning: (settings: Readonly<{ keyScope: KeyScope }>) =>
      request<{ keyScope: KeyScope }>("POST", "/v1/application", settings),
  });
}
