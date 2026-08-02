export function scrubLiveProviderEnvironment(environment) {
  return Object.fromEntries(
    Object.entries(environment).filter(([name]) => {
      const canonical = name.toUpperCase();
      return !(
        canonical.startsWith("INFURA_") ||
        canonical.startsWith("ALCHEMY_") ||
        canonical === "PARITY_RPC_URL" ||
        canonical === "ZERODEV_PROJECT_ID" ||
        /(?:^|_)RPC(?:_URL)?$/u.test(canonical)
      );
    }),
  );
}
