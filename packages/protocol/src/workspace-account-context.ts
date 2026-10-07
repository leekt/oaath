/**
 * The selected logical account in one personal or team workspace.
 *
 * @author taek <leekt216@gmail.com>
 */
import { capturedByProtocol, protocolFailure } from "./errors.js";
import { parseClientId } from "./ids.js";
import { type CaptureContext, type CaptureFailure, exactRecord } from "./internal/exact-record.js";

export const OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION =
  "oaath.workspace-account-context/v1" as const;

/** A selected logical account in one personal or team workspace. */
export interface WorkspaceAccountContext {
  readonly version: typeof OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION;
  readonly workspaceId: string;
  readonly workspaceKind: "personal" | "team";
  readonly accountId: string;
}

function captureWorkspaceAccountContext(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<WorkspaceAccountContext> {
  const record = exactRecord(
    value,
    ["version", "workspaceId", "workspaceKind", "accountId"],
    "workspace account context",
    context,
    fail,
  );
  if (
    record.version !== OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION ||
    (record.workspaceKind !== "personal" && record.workspaceKind !== "team")
  ) {
    return fail("workspace account context version or kind is unsupported");
  }
  return Object.freeze({
    version: OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
    workspaceId: parseClientId(record.workspaceId, fail),
    workspaceKind: record.workspaceKind,
    accountId: parseClientId(record.accountId, fail),
  });
}

export function parseWorkspaceAccountContext(value: unknown): Readonly<WorkspaceAccountContext> {
  return capturedByProtocol(
    "workspace_account_context_invalid",
    "workspace account context is invalid",
    () =>
      captureWorkspaceAccountContext(
        value,
        new WeakSet(),
        protocolFailure("workspace_account_context_invalid"),
      ),
  );
}
