import { describe, expect, it } from "vitest";
import { validatePackageBoundary } from "../scripts/package-boundary.mjs";

const validManifest = Object.freeze({
  name: "@oaath/sdk",
  version: "0.0.0",
  repository: "https://github.com/leekt/oaath",
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
      { ...validManifest, devDependencies: { viem: "workspace:*" } },
    ],
    ["a git transport", { ...validManifest, devDependencies: { viem: "git://example/viem" } }],
    [
      "a disguised git tarball",
      {
        ...validManifest,
        devDependencies: { viem: "git+https://github.com/wevm/viem.tgz" },
      },
    ],
    [
      "a disguised GitHub shorthand tarball",
      { ...validManifest, dependencies: { viem: "github:wevm/viem.tgz" } },
    ],
    [
      "a floating remote tarball",
      {
        ...validManifest,
        dependencies: { viem: "https://github.com/wevm/viem/archive/main.tgz" },
      },
    ],
    ["a GitHub shorthand", { ...validManifest, dependencies: { viem: "wevm/viem" } }],
    ["a linked checkout", { ...validManifest, dependencies: { viem: "link:../viem" } }],
    ["a file checkout", { ...validManifest, dependencies: { viem: "file:../viem" } }],
    ["an old-repository path", { ...validManifest, repository: "leekt/deployer" }],
  ])("rejects %s", (_label, manifest) => {
    expect(() => validatePackageBoundary(manifest)).toThrow();
  });

  it("accepts an intra-workspace @oaath dependency", () => {
    expect(() =>
      validatePackageBoundary({
        ...validManifest,
        dependencies: { "@oaath/protocol": "workspace:*" },
      }),
    ).not.toThrow();
  });

  it("accepts an exact local tarball", () => {
    expect(() =>
      validatePackageBoundary({
        ...validManifest,
        dependencies: { viem: "file:../artifacts/viem-2.55.8.tgz" },
      }),
    ).not.toThrow();
  });
});
