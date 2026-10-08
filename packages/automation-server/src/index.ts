/**
 * `@oaath/automation-server` — a self-hostable automation service: one
 * process with the HTTP API, scheduler and executors, PostgreSQL as its only
 * dependency, and an OAAth issuer as its OAuth authorization server.
 *
 * @author taek <leekt216@gmail.com>
 */
export type { AutomationServiceConfig, ChainEndpoints } from "./config.js";
export { ConfigError, configFromEnv, loadDefinitions } from "./config.js";
export { AUTOMATION_SCHEMA_VERSION } from "./db.js";
export type { Observation, OpenGateway, OperationGateway } from "./executor.js";
export type { AutomationService, StartOptions } from "./service.js";
export { startAutomationService } from "./service.js";
