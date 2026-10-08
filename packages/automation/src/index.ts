/**
 * `@oaath/automation` — declarative automations for OAAth Grants.
 *
 * - `defineAutomation` / `parseAutomation`: the one definition schema owner.
 * - `createPlanTerms`, `resolveCalls`, `derivePlanPolicy`: what a plan freezes,
 *   executes and asks its owner to approve. Pure, shared by the service and
 *   any consent UI.
 * - `createAutomation`: the browser client of an automation service, using a
 *   short-lived session token. It holds no keys and polls no chain.
 *
 * The application backend issues sessions with `@oaath/automation/server`.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { GrantPolicy } from "@oaath/protocol";
import type { Address, AutomationDefinition, Hex } from "./definition.js";
import { AutomationError } from "./error.js";
import type { AutomationParamValue, AutomationPlanTerms } from "./plan.js";
import { type AutomationClientOptions, createTransport } from "./transport.js";

export type {
  Address,
  AutomationAbiItem,
  AutomationAbiParameter,
  AutomationArgument,
  AutomationCall,
  AutomationContract,
  AutomationDefinition,
  AutomationDefinitionInput,
  AutomationFunction,
  AutomationParam,
  AutomationSchedule,
  AutomationValueType,
  Hex,
  NormalizedAutomationCall,
} from "./definition.js";
export {
  AUTOMATION_DEFINITION_VERSION,
  canonicalJson,
  contractFunction,
  defineAutomation,
  encodeCall,
  functionSelector,
  hashAutomation,
  parseAutomation,
} from "./definition.js";
export { AutomationError } from "./error.js";
export type {
  AutomationParamValue,
  AutomationPlanInput,
  AutomationPlanSchedule,
  AutomationPlanTerms,
  ResolvedCall,
} from "./plan.js";
export {
  AUTOMATION_PLAN_VERSION,
  createPlanTerms,
  derivePlanPolicy,
  hashPlanTerms,
  planOperationCount,
  resolveCalls,
  slotTime,
} from "./plan.js";
export type { AutomationClientOptions } from "./transport.js";

export type KeyScope = "user" | "application";

export type PlanStatus =
  | "draft"
  | "awaiting_consent"
  | "authorized"
  | "active"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "expired"
  | "failed";

export type RunStatus =
  | "due"
  | "claimed"
  | "prepared"
  | "submitted"
  | "observed"
  | "finalized"
  | "failed"
  | "skipped";

export interface Session {
  readonly token: string;
  readonly expiresAt: number;
  readonly account: Address;
  readonly keyScope: KeyScope;
}

export interface CreatePlan {
  /** The automation definition id, e.g. `dca.v1`. */
  readonly automation: string;
  readonly params?: Readonly<Record<string, AutomationParamValue>>;
  readonly occurrences?: number;
  readonly startAt?: number;
  /** Reuse only for identical input; changed input under the same key conflicts. */
  readonly idempotencyKey: string;
}

export interface Plan {
  readonly id: Hex;
  readonly automation: Readonly<{ id: string; name: string; hash: Hex }>;
  readonly keyScope: KeyScope;
  readonly status: PlanStatus;
  readonly revision: number;
  readonly terms: AutomationPlanTerms;
  /** The policy the owner approves; null until authorization starts. */
  readonly permission: Readonly<GrantPolicy> | null;
  /** The session key's address the Grant names. */
  readonly signer: Address | null;
  readonly grantId: string | null;
  readonly progress: Readonly<Record<RunStatus, number>>;
  readonly nextSlot: number;
  readonly nextAt: number;
  readonly diagnostic: string | null;
  readonly asOf: number;
}

export interface Run {
  readonly kind: "setup" | "occurrence" | "cancel";
  readonly slot: number | null;
  readonly status: RunStatus;
  readonly scheduledAt: number;
  readonly closesAt: number | null;
  /** The UserOperation hash once journaled; never a reason to resend. */
  readonly operation: Hex | null;
  readonly transactionHash: Hex | null;
  readonly reason: string | null;
}

export interface Authorization {
  readonly plan: Plan;
  /** Open in a popup or redirect; the issuer's portal shows the exact policy. */
  readonly authorizationUrl: string | null;
}

/** The browser client. Memoize it for the lifetime of the mounted integration. */
export function createAutomation(options: AutomationClientOptions) {
  const request = createTransport(options);
  const path = (id: string) => {
    if (!/^0x[0-9a-f]{64}$/u.test(id)) throw new AutomationError("plan_id_invalid", 0);
    return `/v1/plans/${id}`;
  };
  return Object.freeze({
    automations: () =>
      request<{ automations: readonly AutomationDefinition[] }>("GET", "/v1/automations"),
    create: (input: CreatePlan) => request<Plan>("POST", "/v1/plans", input),
    get: (id: string) => request<Plan>("GET", path(id)),
    list: () => request<{ plans: readonly Plan[] }>("GET", "/v1/plans"),
    runs: (id: string, page: Readonly<{ after?: number; limit?: number }> = {}) =>
      request<{ runs: readonly Run[] }>(
        "GET",
        `${path(id)}/runs?${new URLSearchParams({
          after: String(page.after ?? -1),
          limit: String(page.limit ?? 50),
        })}`,
      ),
    /** Starts (or returns the pending) OAuth authorization at the issuer. */
    authorize: (id: string, input: Readonly<{ returnTo?: string }> = {}) =>
      request<Authorization>("POST", `${path(id)}/authorize`, input),
    pause: (id: string) => request<Plan>("POST", `${path(id)}/pause`, {}),
    resume: (id: string) => request<Plan>("POST", `${path(id)}/resume`, {}),
    cancel: (id: string) => request<Plan>("POST", `${path(id)}/cancel`, {}),
  });
}

export type AutomationClient = ReturnType<typeof createAutomation>;
