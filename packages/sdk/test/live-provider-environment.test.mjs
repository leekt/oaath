import { describe, expect, it } from "vitest";
import { scrubLiveProviderEnvironment } from "../scripts/live-provider-environment.mjs";

describe("normal gate environment", () => {
  it("removes live-provider and generic RPC variables", () => {
    expect(
      scrubLiveProviderEnvironment({
        PATH: "/bin",
        INFURA_API_KEY: "secret",
        ALCHEMY_RPC_URL: "secret",
        PARITY_RPC_URL: "secret",
        ZERODEV_PROJECT_ID: "secret",
        ETH_RPC_URL: "secret",
        RPC_URL: "secret",
      }),
    ).toEqual({ PATH: "/bin" });
  });

  it("removes Apple push credentials", () => {
    expect(
      scrubLiveProviderEnvironment({
        PATH: "/bin",
        APNS_KEY_ID: "secret",
        APNS_PRIVATE_KEY: "secret",
        APNS_TOPIC: "secret",
        APPLE_TEAM_ID: "secret",
        apple_private_key: "secret",
      }),
    ).toEqual({ PATH: "/bin" });
  });

  it("does not mutate the caller's environment object", () => {
    const environment = { PATH: "/bin", RPC_URL: "secret" };
    scrubLiveProviderEnvironment(environment);
    expect(environment).toEqual({ PATH: "/bin", RPC_URL: "secret" });
  });
});
