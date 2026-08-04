/**
 * Owns: the one repo-level deny list of live-provider credentials.
 *
 * Repo-owned because it spans packages: it names RPC providers `@oaath/sdk`
 * could reach and the Apple push credentials `@oaath/server` could reach, so no
 * package owns another's credential policy. `scrub-live-rpc-env.mjs` is the only
 * consumer, wired as the vitest `globalSetup` for every project.
 *
 * There is exactly one list. Extend this function; never add a second.
 *
 * @author taek <leekt216@gmail.com>
 */
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
