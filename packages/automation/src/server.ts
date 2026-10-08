import type { Address, ClientOptions, KeyScope, Session } from "./index.js";
import { createTransport } from "./transport.js";
/** Application credentials belong only in the integrating backend. Derive userId/account from its authenticated session. */
export function createAutomationServer(options: ClientOptions) {
	const request = createTransport(options);
	return Object.freeze({
		createSession: (identity: { userId: string; account: Address }) =>
			request<Session>("POST", "/v1/sessions", identity),
		configureSigning: (settings: { keyScope: KeyScope }) =>
			request<{ keyScope: KeyScope }>("POST", "/v1/application", settings),
	});
}
