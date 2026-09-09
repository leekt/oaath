import { createAnvilChain } from "../browser/anvil-chain.mjs";

/** Local networks have their own lifetime, independent of the HTTP service. */
export async function startPhoneDevnet() {
  const chains = [];
  const close = async () => {
    const results = await Promise.allSettled(chains.map((chain) => chain.stop()));
    const errors = results
      .filter((result) => result.status === "rejected")
      .map((result) => result.reason);
    if (errors.length) throw new AggregateError(errors, "phone devnet cleanup failed");
  };
  try {
    for (const chainId of [84_532, 421_614])
      chains.push(await createAnvilChain(chainId, { p256: true }));
    return { chains, close };
  } catch (error) {
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], "phone devnet startup failed", { cause: error });
    }
    throw error;
  }
}
