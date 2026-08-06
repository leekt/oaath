/**
 * The adopter surface: one constructor, the lifecycle handles it returns, and
 * the one closed error vocabulary. Everything else — Kernel primitives,
 * custom-deployment ports, persistence adapters, deterministic test stores —
 * lives behind an explicit subpath (`@oaath/sdk/kernel`, `/advanced`,
 * `/persistence`, `/testing`) so the default import teaches exactly one
 * product path.
 *
 * @author taek <leekt216@gmail.com>
 */
export type {
  OaathConnection,
  OaathPermissionCallInput,
  OaathPermissionInput,
  OaathRequestPermissionInput,
} from "./client/connection.js";
export type { OaathClientErrorCode } from "./client/errors.js";
export { OaathClientError } from "./client/errors.js";
export type {
  OaathCallInput,
  OaathGrantHandle,
  OaathSendCallsInput,
} from "./client/grant-handle.js";
export type {
  OaathOperationHandle,
  OaathOperationLog,
  OaathOperationOutcome,
  OaathOperationReceipt,
  OaathOperationStatus,
} from "./client/operation-handle.js";
export type { Oaath } from "./create-oaath.js";
export { createOAAth } from "./create-oaath.js";
