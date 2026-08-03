// ponytail: this deny list is repo-level policy but lives under packages/sdk;
// it now encodes @oaath/server-owned credentials (APNS_*/APPLE_*) — move it to
// a repo-owned home (or @oaath/testing) so no package owns another's
// credential policy. Do NOT write a second list; extend this one.
export function scrubLiveProviderEnvironment(environment) {
  return Object.fromEntries(
    Object.entries(environment).filter(([name]) => {
      const canonical = name.toUpperCase();
      return !(
        canonical.startsWith("INFURA_") ||
        canonical.startsWith("ALCHEMY_") ||
        canonical === "PARITY_RPC_URL" ||
        canonical === "ZERODEV_PROJECT_ID" ||
        // Apple push credentials are live-provider credentials: a signing key in
        // the gate environment is exactly what this rule exists to remove.
        canonical.startsWith("APNS_") ||
        canonical.startsWith("APPLE_") ||
        /(?:^|_)RPC(?:_URL)?$/u.test(canonical)
      );
    }),
  );
}
