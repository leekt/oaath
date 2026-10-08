import type { Plan, Run } from "@oaath/automation";
import { describe, expect, it } from "vitest";
import { pingSlots } from "../src/runs.js";

const START = 1_800_000_000;
const plan = (status: Plan["status"]) =>
  ({ status, terms: { schedule: { startAt: START, every: 60, occurrences: 3 } } }) as Plan;
const run = (
  slot: number | null,
  status: Run["status"],
  kind: Run["kind"] = "occurrence",
): Run => ({
  kind,
  slot,
  status,
  scheduledAt: START + (slot ?? 0) * 60 + 5,
  closesAt: null,
  operation: null,
  transactionHash: ["observed", "finalized"].includes(status) ? `0x${"ab".repeat(32)}` : null,
  reason: null,
});

describe("ping slots", () => {
  it("lists every occurrence, scheduled until the service runs it", () => {
    expect(pingSlots(plan("awaiting_consent"), [])).toEqual([
      { slot: 0, at: START, state: "scheduled", transactionHash: null },
      { slot: 1, at: START + 60, state: "scheduled", transactionHash: null },
      { slot: 2, at: START + 120, state: "scheduled", transactionHash: null },
    ]);
  });

  it("maps run status to sent, included, failed or skipped, and ignores setup runs", () => {
    const slots = pingSlots(plan("active"), [
      run(null, "finalized", "setup"),
      run(0, "finalized"),
      run(1, "submitted"),
      run(2, "claimed"),
    ]);
    expect(slots.map((slot) => slot.state)).toEqual(["included", "sent", "scheduled"]);
    expect(slots[0]?.transactionHash).toBe(`0x${"ab".repeat(32)}`);
    expect(slots[0]?.at).toBe(START + 5);
    expect(slots[1]?.transactionHash).toBeNull();
    expect(
      pingSlots(plan("failed"), [run(0, "observed"), run(1, "failed")]).map((slot) => slot.state),
    ).toEqual(["included", "failed", "skipped"]);
  });
});
