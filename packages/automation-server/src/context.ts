/**
 * What every part of one service process shares: configuration, the pool,
 * the definitions by id, the budgeted chain ports, and the clock.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { AutomationDefinition, AutomationPlanTerms } from "@oaath/automation";
import type { GrantPolicy } from "@oaath/protocol";
import type { OaathBindingInput } from "@oaath/sdk/advanced";
import type { CetaneChainCapability } from "@oaath/sdk/cetane";
import type { AutomationServiceConfig } from "./config.js";
import type { Pool } from "./db.js";

export interface ServiceContext {
  readonly config: AutomationServiceConfig;
  readonly pool: Pool;
  readonly definitions: ReadonlyMap<string, AutomationDefinition>;
  /** The chain's ports for the current budget window. */
  readonly chain: (chainId: number) => Readonly<CetaneChainCapability>;
  /** Unix seconds at which exhausted provider budgets reopen, or null. */
  readonly budgetRetryAt: () => number | null;
  readonly now: () => number;
  /** Identifies this replica's leases. */
  readonly replicaId: string;
}

/** One `automation_plans` row as read from PostgreSQL. */
export interface PlanRow {
  readonly id: `0x${string}`;
  readonly app_id: string;
  readonly user_id: string;
  readonly account: `0x${string}`;
  readonly key_scope: "user" | "application";
  readonly automation_id: string;
  readonly definition: AutomationDefinition;
  readonly terms: AutomationPlanTerms;
  readonly plan_hash: `0x${string}`;
  readonly status: string;
  readonly revision: number;
  readonly signer_scope: string | null;
  readonly signer: `0x${string}` | null;
  readonly permission: GrantPolicy | null;
  readonly oauth_state: string | null;
  readonly oauth: unknown;
  readonly return_to: string | null;
  readonly next_consent_at: number | null;
  readonly grant_id: string | null;
  readonly binding: OaathBindingInput | null;
  readonly next_slot: number;
  readonly next_at: number;
  readonly created_at: number;
  readonly diagnostic: string | null;
}

export class ServiceError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status = 409) {
    super(code);
    this.name = "ServiceError";
    this.code = code;
    this.status = status;
  }
}

export async function readPlan(pool: Pool, id: string): Promise<PlanRow> {
  const row = (await pool.query("SELECT * FROM automation_plans WHERE id=$1", [id])).rows[0];
  if (row === undefined) throw new ServiceError("plan_not_found", 404);
  return row as PlanRow;
}
