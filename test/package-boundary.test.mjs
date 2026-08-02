import { describe, expect, it } from "vitest";
import { validatePackageBoundary } from "../scripts/package-boundary.mjs";

const validManifest = Object.freeze({
  name: "@leekt/ogp",
  version: "0.0.0",
  repository: "https://github.com/leekt/ogp",
});

describe("package boundary", () => {
  it("accepts the clean pre-release package identity", () => {
    expect(() => validatePackageBoundary(validManifest)).not.toThrow();
  });

  it.each([
    ["a 1.0 version", { ...validManifest, version: "1.0.0" }],
    ["a Moesi dependency", { ...validManifest, devDependencies: { moesi: "^0.12.0" } }],
    [
      "a cross-repository workspace dependency",
      { ...validManifest, dependencies: { viem: "workspace:*" } },
    ],
    ["an old-repository path", { ...validManifest, repository: "leekt/deployer" }],
  ])("rejects %s", (_label, manifest) => {
    expect(() => validatePackageBoundary(manifest)).toThrow();
  });
});
