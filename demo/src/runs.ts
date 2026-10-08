/**
 * The plan's ping slots as the demo shows them: one row per occurrence, from
 * the automation service's plan and run history.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { Plan, Run } from "@oaath/automation";

export type PingState = "scheduled" | "sent" | "included" | "failed" | "skipped";

export interface PingSlot {
  readonly slot: number;
  /** Unix seconds the slot is due. */
  readonly at: number;
  readonly state: PingState;
  readonly transactionHash: `0x${string}` | null;
}

const ENDED = new Set(["completed", "cancelled", "expired", "failed"]);

function stateOf(run: Run): PingState {
  switch (run.status) {
    case "submitted":
      return "sent";
    case "observed":
    case "finalized":
      return "included";
    case "failed":
      return "failed";
    case "skipped":
      return "skipped";
    default:
      return "scheduled";
  }
}

/** Every occurrence slot of `plan`, in order; a slot the ended plan never ran is skipped. */
export function pingSlots(plan: Plan, runs: readonly Run[]): PingSlot[] {
  const { startAt, every, occurrences } = plan.terms.schedule;
  return Array.from({ length: occurrences }, (_, slot) => {
    const run = runs.find(
      (candidate) => candidate.kind === "occurrence" && candidate.slot === slot,
    );
    if (!run)
      return {
        slot,
        at: startAt + slot * every,
        state: ENDED.has(plan.status) ? "skipped" : "scheduled",
        transactionHash: null,
      };
    return {
      slot,
      at: run.scheduledAt,
      state: stateOf(run),
      transactionHash: run.transactionHash,
    };
  });
}
