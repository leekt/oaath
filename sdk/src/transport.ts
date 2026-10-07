import { AutomationError, type ClientOptions } from "./index.js";
export function createTransport(options: ClientOptions) {
	const url = new URL(options.baseUrl);
	if (
		!["http:", "https:"].includes(url.protocol) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash
	)
		throw new AutomationError("base_url_invalid", 0);
	const base = url.href.replace(/\/$/, "");
	const fetcher = options.fetch ?? globalThis.fetch;
	async function request<T>(
		method: string,
		path: string,
		body?: unknown,
	): Promise<T> {
		const token =
			typeof options.token === "function"
				? await options.token()
				: options.token;
		let r: Response;
		try {
			r = await fetcher(base + path, {
				method,
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/json",
				},
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
				signal: AbortSignal.timeout(options.timeoutMs ?? 30000),
				redirect: "error",
			});
		} catch {
			throw new AutomationError("request_outcome_unknown", 0);
		}
		const value: unknown = await r.json().catch(() => {
			throw new AutomationError("response_unreadable", r.status);
		});
		if (!r.ok) {
			const code = (value as { error?: { code?: unknown } })?.error?.code;
			throw new AutomationError(
				typeof code === "string" && /^[a-z0-9_]{1,100}$/.test(code)
					? code
					: "request_failed",
				r.status,
			);
		}
		if (!value || typeof value !== "object")
			throw new AutomationError("response_invalid", r.status);
		return value as T;
	}
	return request;
}
