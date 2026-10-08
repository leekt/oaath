/**
 * DCA as one declarative automation: approve and open a plan once, buy once
 * per occurrence, and on cancellation stop the plan and clear the allowance.
 * Budget, timing, single use per slot and the oracle price bound are enforced
 * by the shared `DcaExecutor` contract, not by this configuration.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type AutomationAbiItem,
  type AutomationDefinition,
  defineAutomation,
} from "@oaath/automation";
import artifact from "./contracts/artifacts/DcaExecutor.json" with { type: "json" };

const TOKEN_APPROVE: AutomationAbiItem = {
  type: "function",
  name: "approve",
  stateMutability: "nonpayable",
  inputs: [
    { name: "spender", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  outputs: [{ name: "", type: "bool" }],
};

const DCA_FUNCTIONS = new Set(["open", "execute", "cancel"]);

export interface DcaAutomationInput {
  readonly chainId: number;
  /** The market's 6-decimal sell token (REPLACE per deployment). */
  readonly sellToken: `0x${string}`;
  /** The deployed shared `DcaExecutor` for that market (REPLACE per deployment). */
  readonly dca: `0x${string}`;
  readonly every?: number | string;
  readonly grace?: number | string;
  readonly maxOccurrences?: number;
}

export function dcaAutomation(input: DcaAutomationInput): AutomationDefinition {
  return defineAutomation({
    id: "dca.v1",
    name: "Recurring purchase",
    chainId: input.chainId,
    contracts: {
      token: { address: input.sellToken, abi: [TOKEN_APPROVE] },
      dca: {
        address: input.dca,
        abi: (artifact.abi as AutomationAbiItem[]).filter(
          (item) => item.type === "function" && DCA_FUNCTIONS.has(item.name ?? ""),
        ),
      },
    },
    params: {
      budget: {
        type: "uint256",
        label: "Total budget (sell token base units)",
        decimals: 6,
        min: "1",
      },
      maxSlippageBps: { type: "uint16", label: "Max slippage (bps)", max: "1000" },
    },
    schedule: {
      every: input.every ?? "1d",
      count: { max: input.maxOccurrences ?? 365 },
      grace: input.grace ?? "15m",
    },
    setup: [
      { contract: "token", function: "approve", args: ["$contract.dca", "$param.budget"] },
      {
        contract: "dca",
        function: "open",
        args: [
          "$plan.id",
          "$param.budget",
          "$plan.occurrences",
          "$plan.startAt",
          "$plan.every",
          "$plan.grace",
          "$param.maxSlippageBps",
        ],
      },
    ],
    call: { contract: "dca", function: "execute", args: ["$plan.id", "$slot.index"] },
    cancel: [
      { contract: "dca", function: "cancel", args: ["$plan.id"] },
      { contract: "token", function: "approve", args: ["$contract.dca", "0"] },
    ],
  });
}
