/**
 * The service's whole configuration, captured once from the environment.
 * Nothing here is logged: URLs may carry provider credentials.
 *
 * @author taek <leekt216@gmail.com>
 */
import { readFileSync } from "node:fs";
import { type AutomationDefinition, parseAutomation } from "@oaath/automation";

export interface ChainEndpoints {
  readonly rpcUrl: string;
  readonly bundlerUrl: string;
  /** An ERC-7677 paymaster service; operations are self-funded without it. */
  readonly paymasterUrl: string | null;
}

export interface AutomationServiceConfig {
  readonly databaseUrl: string;
  /** 32-byte AES-256-GCM key sealing session keys and OAuth verifiers at rest. */
  readonly sealKey: Buffer;
  /** The service's external base URL; the OAuth redirect URI hangs off it. */
  readonly publicUrl: string;
  readonly listen: Readonly<{ host: string; port: number }>;
  readonly issuer: string;
  readonly clientId: string;
  /** Application credentials as SHA-256 hex of the bearer token. */
  readonly applications: readonly Readonly<{ id: string; tokenSha256: string }>[];
  /** Browser origins allowed to call the API with a session token. */
  readonly allowedOrigins: readonly string[];
  readonly definitions: readonly AutomationDefinition[];
  readonly chains: ReadonlyMap<number, ChainEndpoints>;
  readonly budgets: Readonly<{
    rpc: number;
    bundler: number;
    paymaster: number;
    windowSeconds: number;
  }>;
}

export class ConfigError extends Error {
  readonly code = "config_invalid" as const;
  constructor(readonly variable: string) {
    super(`${variable} is missing or invalid`);
    this.name = "ConfigError";
  }
}

type Env = Readonly<Record<string, string | undefined>>;

function required(env: Env, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim() === "") throw new ConfigError(name);
  return value.trim();
}

function httpUrl(env: Env, name: string, value = required(env, name)): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(name);
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new ConfigError(name);
  return value.replace(/\/$/u, "");
}

function positive(env: Env, name: string, fallback: number): number {
  const value = env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new ConfigError(name);
  return parsed;
}

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Reads definitions from JSON files: one definition or an array of them per file. */
export function loadDefinitions(paths: readonly string[]): AutomationDefinition[] {
  const definitions: AutomationDefinition[] = [];
  for (const path of paths) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new ConfigError("AUTOMATION_DEFINITIONS");
    }
    for (const entry of Array.isArray(parsed) ? parsed : [parsed])
      definitions.push(parseAutomation(entry));
  }
  return definitions;
}

export function configFromEnv(
  env: Env,
  definitions: readonly AutomationDefinition[] = loadDefinitions(list(env.AUTOMATION_DEFINITIONS)),
): AutomationServiceConfig {
  const sealKey = Buffer.from(required(env, "AUTOMATION_SEAL_KEY"), "hex");
  if (sealKey.length !== 32) throw new ConfigError("AUTOMATION_SEAL_KEY");
  const [host, port] = (env.AUTOMATION_LISTEN ?? "127.0.0.1:4317").split(/:(?=[0-9]+$)/u);
  if (!host || !port || !Number.isSafeInteger(Number(port)))
    throw new ConfigError("AUTOMATION_LISTEN");

  const applications = list(env.AUTOMATION_APPLICATIONS).map((entry) => {
    const [id, tokenSha256] = entry.split(":");
    if (
      !id ||
      !/^[A-Za-z0-9._-]{1,64}$/u.test(id) ||
      !tokenSha256 ||
      !/^[0-9a-f]{64}$/u.test(tokenSha256)
    )
      throw new ConfigError("AUTOMATION_APPLICATIONS");
    return Object.freeze({ id, tokenSha256 });
  });
  if (applications.length === 0) throw new ConfigError("AUTOMATION_APPLICATIONS");

  if (definitions.length === 0) throw new ConfigError("AUTOMATION_DEFINITIONS");
  if (new Set(definitions.map((definition) => definition.id)).size !== definitions.length)
    throw new ConfigError("AUTOMATION_DEFINITIONS");

  const chains = new Map<number, ChainEndpoints>();
  for (const chainId of new Set(definitions.map((definition) => definition.chainId))) {
    const paymaster = env[`AUTOMATION_PAYMASTER_URL_${chainId}`];
    chains.set(
      chainId,
      Object.freeze({
        rpcUrl: httpUrl(env, `AUTOMATION_RPC_URL_${chainId}`),
        bundlerUrl: httpUrl(env, `AUTOMATION_BUNDLER_URL_${chainId}`),
        paymasterUrl:
          paymaster === undefined || paymaster === ""
            ? null
            : httpUrl(env, `AUTOMATION_PAYMASTER_URL_${chainId}`, paymaster),
      }),
    );
  }

  return Object.freeze({
    databaseUrl: required(env, "DATABASE_URL"),
    sealKey,
    publicUrl: httpUrl(env, "AUTOMATION_PUBLIC_URL"),
    listen: Object.freeze({ host, port: Number(port) }),
    issuer: httpUrl(env, "OAATH_ISSUER"),
    clientId: required(env, "OAATH_CLIENT_ID"),
    applications: Object.freeze(applications),
    allowedOrigins: Object.freeze(list(env.AUTOMATION_ALLOWED_ORIGINS)),
    definitions: Object.freeze([...definitions]),
    chains,
    budgets: Object.freeze({
      rpc: positive(env, "AUTOMATION_RPC_BUDGET", 3000),
      bundler: positive(env, "AUTOMATION_BUNDLER_BUDGET", 300),
      paymaster: positive(env, "AUTOMATION_PAYMASTER_BUDGET", 100),
      windowSeconds: positive(env, "AUTOMATION_BUDGET_WINDOW_SECONDS", 600),
    }),
  });
}
