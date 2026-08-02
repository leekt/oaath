export function validatePackageBoundary(manifest) {
  if (manifest.name !== "@leekt/ogp") {
    throw new Error("package name must remain @leekt/ogp");
  }

  if (!/^0\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(manifest.version)) {
    throw new Error("package version must remain pre-1.0");
  }

  const dependencyGroups = [
    ["dependencies", manifest.dependencies],
    ["devDependencies", manifest.devDependencies],
    ["optionalDependencies", manifest.optionalDependencies],
    ["peerDependencies", manifest.peerDependencies],
  ];

  for (const [group, dependencies] of dependencyGroups) {
    for (const [name, range] of Object.entries(dependencies ?? {})) {
      if (name === "moesi" || name.startsWith("@moesi/")) {
        throw new Error(`${group} must not depend on Moesi: ${name}`);
      }
      if (typeof range === "string" && /^(?:workspace:|git\+|github:)/u.test(range)) {
        throw new Error(`${group} must use released packages or exact tarballs: ${name}`);
      }
    }
  }

  if (JSON.stringify(manifest).includes("leekt/deployer")) {
    throw new Error("package metadata must not retain the old implementation repository");
  }
}
