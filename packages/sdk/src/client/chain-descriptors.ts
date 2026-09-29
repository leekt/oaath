/**
 * The chain port implementation is an optional setting. Plain per-chain
 * descriptors build the default viem ports; an array of chain capabilities is
 * the explicit override and passes through untouched.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createViemChainPorts, type ViemChainPortConfiguration } from "../viem/chain-ports.js";
import { OaathRpcError } from "../viem/rpc.js";
import { clientFail } from "./errors.js";

/** One chain's public RPC and ERC-4337 endpoints, keyed by chain ID. */
export type OaathChainDescriptor = ViemChainPortConfiguration;

/** Plain descriptors, or custom chain capabilities as the explicit override. */
export type OaathChains<Capability> =
  | readonly Readonly<Capability>[]
  | Readonly<Record<number, Readonly<OaathChainDescriptor>>>;

/**
 * Replaces plain `chains` descriptors with the default viem ports. Building
 * them makes no request; each configuration owns its own request budget.
 */
export function withDefaultChainPorts(
  configuration: unknown,
  record: Readonly<Record<string, unknown>>,
): unknown {
  if (!Object.hasOwn(record, "chains") || Array.isArray(record.chains)) return configuration;
  try {
    return { ...record, chains: createViemChainPorts(record.chains as never) };
  } catch (error) {
    if (error instanceof OaathRpcError) {
      return clientFail("oaath_client_input_invalid", "chain descriptors are invalid", error.code);
    }
    throw error;
  }
}
