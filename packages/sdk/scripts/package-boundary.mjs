export function validatePackageBoundary(manifest) {
  if (manifest.name !== "@oaath/sdk") {
    throw new Error("package name must remain @oaath/sdk");
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
      if (typeof range === "string" && isSourceDependency(range)) {
        throw new Error(`${group} must use released packages or exact tarballs: ${name}`);
      }
    }
  }

  if (JSON.stringify(manifest).includes("leekt/deployer")) {
    throw new Error("package metadata must not retain the old implementation repository");
  }
}

function isSourceDependency(range) {
  const specifier = range.trim();
  const lower = specifier.toLowerCase();

  if (lower.startsWith("file:")) {
    return !/^file:[^?#]+\.tgz$/u.test(lower);
  }

  return (
    /^(?:workspace:|link:|git:|git\+|github:|gitlab:|bitbucket:|ssh:)/u.test(lower) ||
    /^(?:\.\.?\/|\/)/u.test(lower) ||
    /^git@/u.test(lower) ||
    /^[0-9a-z_.-]+\/[0-9a-z_.-]+(?:#.*)?$/u.test(lower) ||
    /^https?:\/\//u.test(lower)
  );
}
