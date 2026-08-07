/**
 * Cleanup is secondary work with its own durable state.
 *
 * ```text
 * state and owner        the checkpoint record owns "this effect is done"
 * persisted evidence     completed effect names, written only after success
 * resource occupied?     no; every effect is attempted at most once per run
 * retry positively safe? yes, and only for effects absent from the checkpoint
 * transitions            pending -> complete, per effect, monotonically
 * crash/reload           an interrupted run leaves the effects it finished
 *                        recorded; the next run attempts exactly the rest
 * cleanup owner          the caller retries this coordinator
 * ```
 *
 * Rules that never bend: every independent requested effect is attempted even
 * after another fails; destructive dependents wait for their prerequisites;
 * the canonical error that caused cleanup is preserved and re-thrown unchanged;
 * and an effect is recorded complete only after it succeeded.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureDenseArray } from "@oaath/protocol";
import { clientFail, exactClientRecord } from "../client/errors.js";
import {
  isCleanupEffectName,
  OAATH_CLEANUP_CHECKPOINT_VERSION,
  type OaathCleanupCheckpoint,
  type OaathCleanupCheckpointStore,
  type OaathCleanupEffectName,
  parseCleanupCheckpoint,
  persistenceId,
} from "../persistence/interfaces.js";
import type { OaathCleanupEffect } from "./effects.js";

export type CleanupErrorCode = "cleanup_input_invalid" | "cleanup_incomplete";

export class OaathCleanupError extends Error {
  readonly code: CleanupErrorCode;
  /** Effects that neither completed now nor were already complete. */
  readonly unfinished: readonly OaathCleanupEffectName[];
  /** Suppressed diagnostics, one per failed effect. */
  readonly failures: readonly Readonly<{ effect: OaathCleanupEffectName; error: unknown }>[];

  constructor(
    code: CleanupErrorCode,
    message: string,
    unfinished: readonly OaathCleanupEffectName[] = [],
    failures: readonly Readonly<{ effect: OaathCleanupEffectName; error: unknown }>[] = [],
  ) {
    super(message);
    this.name = "OaathCleanupError";
    this.code = code;
    this.unfinished = Object.freeze([...unfinished]);
    this.failures = Object.freeze([...failures]);
  }
}

export interface OaathCleanupResult {
  readonly cleanupId: string;
  readonly completed: readonly OaathCleanupEffectName[];
  readonly unfinished: readonly OaathCleanupEffectName[];
  /** Suppressed cleanup diagnostics; never the reason the caller failed. */
  readonly failures: readonly Readonly<{ effect: OaathCleanupEffectName; error: unknown }>[];
}

export interface RunOaathCleanupInput {
  readonly cleanupId: string;
  readonly effects: readonly OaathCleanupEffect[];
  readonly checkpoints: OaathCleanupCheckpointStore;
  readonly now: () => number;
  /**
   * The canonical error that caused this cleanup, or `null`. It is re-thrown
   * unchanged once every effect has been attempted.
   */
  readonly primaryError: unknown;
}

function captureEffects(value: unknown, context: CaptureContext): readonly OaathCleanupEffect[] {
  const entries = captureDenseArray(value, "cleanup effects", context, (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  const names = new Set<string>();
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactClientRecord(entry, ["name", "run"], `cleanup effect ${index}`, context);
      if (!isCleanupEffectName(record.name) || typeof record.run !== "function") {
        return clientFail("oaath_client_input_invalid", `cleanup effect ${index} is invalid`);
      }
      if (names.has(record.name)) {
        return clientFail("oaath_client_input_invalid", "cleanup effects repeat a name");
      }
      names.add(record.name);
      return Object.freeze({
        name: record.name,
        run: record.run as () => Promise<void>,
      });
    }),
  );
}

async function readCompleted(
  store: OaathCleanupCheckpointStore,
  cleanupId: string,
): Promise<readonly OaathCleanupEffectName[]> {
  let stored: unknown;
  try {
    stored = await store.read(cleanupId);
  } catch {
    // An unreadable checkpoint means nothing is proven complete, so every
    // requested effect is attempted again. Effects are idempotent by contract.
    return Object.freeze([]);
  }
  if (stored === undefined || stored === null) return Object.freeze([]);
  try {
    return parseCleanupCheckpoint(stored).completed;
  } catch {
    return Object.freeze([]);
  }
}

/**
 * Attempts every unfinished effect, records the ones that succeed, and preserves
 * the caller's canonical error.
 */
export async function runOaathCleanup(value: unknown): Promise<Readonly<OaathCleanupResult>> {
  const context: CaptureContext = new WeakSet();
  const captured = exactClientRecord(
    value,
    ["cleanupId", "effects", "checkpoints", "now", "primaryError"],
    "cleanup input",
    context,
  );
  const cleanupId = persistenceId(captured.cleanupId, "cleanupId", (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  const effects = captureEffects(captured.effects, context);
  const store = exactClientRecord(
    captured.checkpoints,
    ["read", "write", "clear", "close"],
    "cleanup checkpoint store",
    context,
    "oaath_client_capability_invalid",
  );
  for (const method of ["read", "write", "clear", "close"]) {
    if (typeof store[method] !== "function") {
      clientFail("oaath_client_capability_invalid", `checkpoint store ${method} is invalid`);
    }
  }
  const checkpoints = captured.checkpoints as OaathCleanupCheckpointStore;
  if (typeof captured.now !== "function") {
    clientFail("oaath_client_input_invalid", "cleanup clock is invalid");
  }
  const now = captured.now as () => number;
  const primaryError = captured.primaryError;

  const completed = new Set<OaathCleanupEffectName>(await readCompleted(checkpoints, cleanupId));
  const failures: Readonly<{ effect: OaathCleanupEffectName; error: unknown }>[] = [];
  const unfinished: OaathCleanupEffectName[] = [];
  const requested = new Set(effects.map((effect) => effect.name));

  for (const effect of effects) {
    if (completed.has(effect.name)) continue;
    const blocked =
      (effect.name === "forgetLocal" && requested.has("revoke") && !completed.has("revoke")) ||
      (effect.name === "close" &&
        effects.some((candidate) =>
          candidate.name === "close" ? false : !completed.has(candidate.name),
        ));
    if (blocked) {
      unfinished.push(effect.name);
      continue;
    }
    try {
      await effect.run();
    } catch (error) {
      // Independent remaining effects are still attempted. Dependents are
      // withheld below so every failed capability remains retryable.
      failures.push(Object.freeze({ effect: effect.name, error }));
      unfinished.push(effect.name);
      continue;
    }
    completed.add(effect.name);
    const checkpoint: OaathCleanupCheckpoint = Object.freeze({
      version: OAATH_CLEANUP_CHECKPOINT_VERSION,
      cleanupId,
      completed: Object.freeze([...completed]),
      updatedAt: now(),
    });
    try {
      await checkpoints.write(checkpoint);
    } catch (error) {
      // The effect is done but unproven, so the next run attempts it again.
      failures.push(Object.freeze({ effect: effect.name, error }));
      if (!unfinished.includes(effect.name)) unfinished.push(effect.name);
      completed.delete(effect.name);
    }
  }

  const result: Readonly<OaathCleanupResult> = Object.freeze({
    cleanupId,
    completed: Object.freeze([...completed]),
    unfinished: Object.freeze([...unfinished]),
    failures: Object.freeze([...failures]),
  });

  if (unfinished.length === 0) {
    try {
      await checkpoints.clear(cleanupId);
    } catch {
      // A stale complete checkpoint only makes a future run skip finished work.
    }
  }
  if (primaryError !== null && primaryError !== undefined) throw primaryError;
  if (unfinished.length > 0) {
    throw new OaathCleanupError(
      "cleanup_incomplete",
      "cleanup left effects unfinished",
      result.unfinished,
      result.failures,
    );
  }
  return result;
}
