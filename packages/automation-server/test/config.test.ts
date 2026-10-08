import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError, configFromEnv, loadDefinitions } from "../src/config.js";
import { CustodyError, open, seal } from "../src/db.js";
import { definition } from "./support/fixture.js";

const env = {
  DATABASE_URL: "postgres://localhost/automation",
  AUTOMATION_SEAL_KEY: "11".repeat(32),
  AUTOMATION_PUBLIC_URL: "https://automation.example/",
  OAATH_ISSUER: "https://issuer.example",
  OAATH_CLIENT_ID: "client-1",
  AUTOMATION_APPLICATIONS: `app:${"ab".repeat(32)}`,
  AUTOMATION_RPC_URL_31337: "http://127.0.0.1:8545",
  AUTOMATION_BUNDLER_URL_31337: "http://127.0.0.1:4337",
};

describe("configFromEnv", () => {
  it("captures every endpoint per definition chain and the default budgets", () => {
    const config = configFromEnv(env, [definition]);
    expect(config.publicUrl).toBe("https://automation.example");
    expect(config.listen).toEqual({ host: "127.0.0.1", port: 4317 });
    expect(config.chains.get(31337)).toEqual({
      rpcUrl: "http://127.0.0.1:8545",
      bundlerUrl: "http://127.0.0.1:4337",
      paymasterUrl: null,
      paymasterApiKey: null,
      relayPaysGas: false,
    });
    expect(config.budgets).toEqual({ rpc: 3000, bundler: 300, paymaster: 100, windowSeconds: 600 });
    expect(config.maxOpenSlots).toBe(4);
    expect(
      configFromEnv({ ...env, AUTOMATION_MAX_OPEN_SLOTS: "2" }, [definition]).maxOpenSlots,
    ).toBe(2);
    expect(() => configFromEnv({ ...env, AUTOMATION_MAX_OPEN_SLOTS: "0" }, [definition])).toThrow(
      expect.objectContaining({ variable: "AUTOMATION_MAX_OPEN_SLOTS" }),
    );
  });

  it("captures an optional paymaster API key only alongside its paymaster", () => {
    const config = configFromEnv(
      {
        ...env,
        AUTOMATION_PAYMASTER_URL_31337: "http://127.0.0.1:4338",
        AUTOMATION_PAYMASTER_API_KEY_31337: "pm-key",
      },
      [definition],
    );
    expect(config.chains.get(31337)).toMatchObject({
      paymasterUrl: "http://127.0.0.1:4338",
      paymasterApiKey: "pm-key",
    });
    expect(() =>
      configFromEnv({ ...env, AUTOMATION_PAYMASTER_API_KEY_31337: "pm-key" }, [definition]),
    ).toThrow(expect.objectContaining({ variable: "AUTOMATION_PAYMASTER_API_KEY_31337" }));
  });

  it("captures a relay-paid bundler and refuses it alongside a paymaster", () => {
    const config = configFromEnv({ ...env, AUTOMATION_RELAY_PAYS_GAS_31337: "true" }, [definition]);
    expect(config.chains.get(31337)).toMatchObject({ paymasterUrl: null, relayPaysGas: true });
    for (const extra of [
      { AUTOMATION_PAYMASTER_URL_31337: "http://127.0.0.1:4338" },
      { AUTOMATION_RELAY_PAYS_GAS_31337: "yes" },
    ])
      expect(() =>
        configFromEnv({ ...env, AUTOMATION_RELAY_PAYS_GAS_31337: "true", ...extra }, [definition]),
      ).toThrow(expect.objectContaining({ variable: "AUTOMATION_RELAY_PAYS_GAS_31337" }));
  });

  it.each([
    ["AUTOMATION_SEAL_KEY", "11"],
    ["AUTOMATION_APPLICATIONS", "app:short"],
    ["AUTOMATION_BUNDLER_URL_31337", undefined],
    ["AUTOMATION_RPC_BUDGET", "0"],
    ["OAATH_ISSUER", "ftp://issuer"],
  ])("names %s when it is invalid", (name, value) => {
    expect(() => configFromEnv({ ...env, [name]: value }, [definition])).toThrow(
      expect.objectContaining({ variable: name }),
    );
  });

  it("loads definitions from JSON files through the schema owner", () => {
    const directory = mkdtempSync(join(tmpdir(), "automation-config-"));
    const file = join(directory, "definitions.json");
    writeFileSync(file, JSON.stringify([definition]));
    expect(loadDefinitions([file])).toEqual([definition]);
    writeFileSync(
      file,
      JSON.stringify({ ...definition, call: { ...definition.call, function: "sweep" } }),
    );
    expect(() => loadDefinitions([file])).toThrow(
      expect.objectContaining({ code: "automation_definition_invalid" }),
    );
    expect(() =>
      configFromEnv({ ...env, AUTOMATION_DEFINITIONS: join(directory, "missing.json") }),
    ).toThrow(ConfigError);
  });
});

describe("sealing", () => {
  it("fails closed on another key, another record, or tampering", () => {
    const key = Buffer.alloc(32, 1);
    const sealed = seal(key, { privateKey: "0x01" }, "signer:a");
    expect(open(key, sealed, "signer:a")).toEqual({ privateKey: "0x01" });
    expect(() => open(Buffer.alloc(32, 2), sealed, "signer:a")).toThrow(CustodyError);
    expect(() => open(key, sealed, "signer:b")).toThrow(CustodyError);
    expect(() =>
      open(
        key,
        { ...sealed, data: `${sealed.data[0] === "0" ? "1" : "0"}${sealed.data.slice(1)}` },
        "signer:a",
      ),
    ).toThrow(CustodyError);
    expect(() => open(key, null, "signer:a")).toThrow(CustodyError);
  });
});
