#!/usr/bin/env node
/**
 * `oaath-automation`: starts one service process from the environment and
 * stops it on SIGINT/SIGTERM. Configuration errors name the variable only.
 *
 * @author taek <leekt216@gmail.com>
 */
import { ConfigError, configFromEnv } from "./config.js";
import { startAutomationService } from "./service.js";

try {
  const service = await startAutomationService(configFromEnv(process.env));
  console.log(JSON.stringify({ event: "automation_listening", url: service.url }));
  const stop = () => {
    service.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
} catch (error) {
  const code =
    error instanceof ConfigError
      ? `config_invalid:${error.variable}`
      : typeof (error as { code?: unknown })?.code === "string"
        ? (error as { code: string }).code
        : "startup_failed";
  console.error(JSON.stringify({ event: "automation_failed", code }));
  process.exit(1);
}
