import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { projectOwnerPhoneRevocation } from "../src/native.js";

const source = JSON.parse(
  readFileSync(
    new URL("../../protocol/test/fixtures/kernel-revocation-operation.json", import.meta.url),
    "utf8",
  ),
);
const golden = JSON.parse(
  readFileSync(new URL("./fixtures/phone-revocation-golden.json", import.meta.url), "utf8"),
);

describe("native revocation consent", () => {
  it.each([0, 1, 2])("projects exact unsigned request %s for the Swift consumer", async (index) => {
    const { name: _name, ...operation } = source.valid[index];
    const projection = await projectOwnerPhoneRevocation({
      operationId: `revoke-${index}`,
      ownerSubject: "fixture-owner",
      expiresAt: 1_800_000_060_000,
      request: {
        version: "oaath.kernel-revocation-signing-request/v1",
        kind: "kernel-revocation",
        permissionRequest: source.permissionRequest,
        install: source.installProjection.scope.request,
        ...operation,
      },
    });
    expect(projection).toEqual(golden[index]);
    expect(projection.client.redirectUri).toBeNull();
    expect(projection.scope.kind).toBe("kernel-revocation");
  });
});
