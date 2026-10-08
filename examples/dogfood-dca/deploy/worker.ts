import { ORIGIN } from "../examples/dca/hosted/policy.js";

type Binding = { fetch(request: Request): Promise<Response> };
export default {
	async fetch(request: Request, env: { ASSETS: Binding; DCA_API: Binding }) {
		const url = new URL(request.url);
		const headers = new Headers({
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
			"x-frame-options": "DENY",
			"content-security-policy":
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
		});
		const respond = (body: BodyInit | null, status: number) =>
			new Response(body, { status, headers });
		if (url.origin !== ORIGIN) return respond("Host denied", 421);
		if (
			request.headers.has("origin") &&
			request.headers.get("origin") !== ORIGIN
		)
			return respond("Origin denied", 403);
		if (url.pathname.startsWith("/api/")) {
			if (!["GET", "POST"].includes(request.method))
				return respond("Method denied", 405);
			if (request.method === "POST" && request.headers.get("origin") !== ORIGIN)
				return respond("Origin required", 403);
			let size = 0;
			const parts: Uint8Array[] = [];
			const reader = request.body?.getReader();
			if (reader)
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					size += value.length;
					if (size > 32768) {
						await reader.cancel();
						return respond("Request too large", 413);
					}
					parts.push(value);
				}
			const bytes = new Uint8Array(size);
			let offset = 0;
			for (const p of parts) {
				bytes.set(p, offset);
				offset += p.length;
			}
			try {
				const response = await env.DCA_API.fetch(
					new Request(`http://127.0.0.1:4320${url.pathname}${url.search}`, {
						method: request.method,
						headers: {
							origin: ORIGIN,
							cookie: request.headers.get("cookie") ?? "",
							"content-type": "application/json",
						},
						body: request.method === "POST" ? bytes : undefined,
						redirect: "manual",
						signal: AbortSignal.timeout(40000),
					}),
				);
				headers.set("cache-control", "no-store");
				headers.set("content-type", "application/json");
				const cookie = response.headers.get("set-cookie");
				if (cookie) headers.set("set-cookie", cookie);
				return respond(
					response.body,
					response.status >= 300 && response.status < 400
						? 502
						: response.status,
				);
			} catch {
				headers.set("content-type", "application/json");
				return respond(JSON.stringify({ error: "service_unavailable" }), 503);
			}
		}
		if (!["GET", "HEAD"].includes(request.method))
			return respond("Method denied", 405);
		if (!["/", "/app.js", "/automation.css"].includes(url.pathname))
			return respond("Not found", 404);
		if (url.pathname === "/") url.pathname = "/index.html";
		const response = await env.ASSETS.fetch(new Request(url, request));
		headers.set(
			"content-type",
			response.headers.get("content-type") ?? "text/plain",
		);
		headers.set("cache-control", "no-cache");
		return respond(response.body, response.status);
	},
};
