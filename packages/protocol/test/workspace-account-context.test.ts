/**
 * The workspace account context: exact capture of a personal or team selection.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
  parseWorkspaceAccountContext,
} from "../src/index.js";

const context = {
  version: OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
  workspaceId: "personal-1",
  workspaceKind: "personal",
  accountId: "account-1",
};

describe("workspace account context", () => {
  it("captures a personal or team selection exactly", () => {
    expect(parseWorkspaceAccountContext(context)).toEqual(context);
    const team = { ...context, workspaceId: "team-1", workspaceKind: "team" };
    expect(parseWorkspaceAccountContext(team)).toEqual(team);
  });

  it.each([
    ["an unknown field", { ...context, extra: true }],
    ["a foreign version", { ...context, version: "oaath.workspace-account-context/v2" }],
    ["an unknown kind", { ...context, workspaceKind: "org" }],
    ["an empty account id", { ...context, accountId: "" }],
  ])("refuses %s", (_, value) => {
    expect(() => parseWorkspaceAccountContext(value)).toThrowError(
      expect.objectContaining({ code: "service_bootstrap_invalid" }),
    );
  });
});
