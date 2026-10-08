import { describe, expect, it } from "vitest";
import { AutomationError, createAutomation } from "../src/index.js";
import { createAutomationServer } from "../src/server.js";

const id = `0x${"ab".repeat(32)}`;

describe("createAutomation", () => {
  it("does not retry an unknown mutation or follow redirects", async () => {
    let calls = 0;
    const client = createAutomation({
      baseUrl: "http://service",
      token: "secret-session-token",
      fetch: async (_, init) => {
        calls += 1;
        expect(init?.redirect).toBe("error");
        throw new Error("secret network diagnostic");
      },
    });
    await expect(client.cancel(id)).rejects.toMatchObject({ code: "request_outcome_unknown" });
    expect(calls).toBe(1);
  });

  it("passes only structured service codes through", async () => {
    const client = createAutomation({
      baseUrl: "http://service",
      token: "secret-session-token",
      fetch: async () => Response.json({ error: { code: "a secret raw error" } }, { status: 409 }),
    });
    await expect(client.get(id)).rejects.toMatchObject({ code: "request_failed", status: 409 });
  });

  it("refuses a malformed plan id before any request", () => {
    const client = createAutomation({ baseUrl: "http://service", token: "t".repeat(16) });
    expect(() => client.get("../sessions")).toThrow(AutomationError);
  });

  it("sends authorize to the plan with its return target", async () => {
    const seen: { url: string; body: unknown }[] = [];
    const client = createAutomation({
      baseUrl: "https://automation.example/",
      token: async () => "session-token-value",
      fetch: async (url, init) => {
        seen.push({ url: String(url), body: JSON.parse(String(init?.body)) });
        return Response.json({ plan: { id }, authorizationUrl: "https://issuer/authorize" });
      },
    });
    const result = await client.authorize(id, { returnTo: "https://app.example/done" });
    expect(result.authorizationUrl).toBe("https://issuer/authorize");
    expect(seen).toEqual([
      {
        url: `https://automation.example/v1/plans/${id}/authorize`,
        body: { returnTo: "https://app.example/done" },
      },
    ]);
  });

  it("rejects credentials in the base URL", () => {
    expect(() => createAutomation({ baseUrl: "https://user:pw@service", token: "x" })).toThrow(
      AutomationError,
    );
  });
});

describe("createAutomationServer", () => {
  it("creates a session with the application credential", async () => {
    const client = createAutomationServer({
      baseUrl: "http://service",
      token: "application-credential",
      fetch: async (url, init) => {
        expect(String(url)).toBe("http://service/v1/sessions");
        expect((init?.headers as Record<string, string> | undefined)?.authorization).toBe(
          "Bearer application-credential",
        );
        return Response.json({ token: "s", expiresAt: 1, account: "0x1", keyScope: "user" });
      },
    });
    expect((await client.createSession({ userId: "u", account: "0x1" })).keyScope).toBe("user");
  });
});
