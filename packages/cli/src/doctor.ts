import {
  encodeKernelV4FactoryImplementationRead,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
} from "@oaath/sdk/kernel";
import { decodeAbiParameters, type Hex, keccak256 } from "viem";
import { type Component, components } from "./manifest.js";
import type { RpcReader } from "./rpc.js";

export type Status = "verified" | "present" | "missing" | "mismatch" | "unreadable";
export interface ComponentReport {
  readonly id: string;
  readonly address: Hex;
  readonly required: boolean;
  readonly status: Status;
  readonly runtimeCodeHash: Hex | null;
}
export interface DoctorReport {
  readonly version: "oaath.runtime-readiness/v1";
  readonly chainId: number;
  readonly observedChainId: number | null;
  readonly checkedAt: string;
  readonly blockNumber: string | null;
  readonly ready: boolean;
  readonly error: "chain_mismatch" | "rpc_unavailable" | null;
  readonly factoryBinding: "verified" | "mismatch" | "unreadable";
  readonly components: readonly ComponentReport[];
}

function quantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(value) || value.length > 66)
    throw new Error("rpc_invalid_quantity");
  return BigInt(value);
}

async function inspect(component: Component, rpc: RpcReader, block: Hex): Promise<ComponentReport> {
  const base = { id: component.id, address: component.address, required: component.required };
  try {
    const code = await rpc.request("eth_getCode", [component.address, block]);
    if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/u.test(code) || code.length > 131_074)
      throw new Error();
    if (code === "0x") return { ...base, status: "missing", runtimeCodeHash: null };
    const hash = keccak256(code as Hex);
    const status =
      component.runtimeCodeHash === null
        ? "present"
        : hash === component.runtimeCodeHash
          ? "verified"
          : "mismatch";
    return { ...base, status, runtimeCodeHash: hash };
  } catch {
    return { ...base, status: "unreadable", runtimeCodeHash: null };
  }
}

/** A readiness snapshot, not a deployment claim or a transaction-finality proof. */
export async function doctor(chainId: number, rpc: RpcReader): Promise<DoctorReport> {
  const manifest = components(chainId);
  const base = {
    version: "oaath.runtime-readiness/v1" as const,
    chainId,
    checkedAt: new Date().toISOString(),
  };
  let observedChainId: number | null = null;
  let block: Hex;
  const failed = (error: DoctorReport["error"]): DoctorReport => ({
    ...base,
    observedChainId,
    blockNumber: null,
    ready: false,
    error,
    factoryBinding: "unreadable",
    components: manifest.map(({ id, address, required }) => ({
      id,
      address,
      required,
      status: "unreadable",
      runtimeCodeHash: null,
    })),
  });
  try {
    const observed = quantity(await rpc.request("eth_chainId"));
    if (observed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error();
    observedChainId = Number(observed);
    if (observedChainId !== chainId) return failed("chain_mismatch");
    block = `0x${quantity(await rpc.request("eth_blockNumber")).toString(16)}`;
  } catch {
    return failed("rpc_unavailable");
  }
  const reports: ComponentReport[] = [];
  // At most four concurrent requests. Every read uses this snapshot's block number.
  for (let offset = 0; offset < manifest.length; offset += 4)
    reports.push(
      ...(await Promise.all(
        manifest.slice(offset, offset + 4).map((component) => inspect(component, rpc, block)),
      )),
    );
  let factoryBinding: DoctorReport["factoryBinding"] = "unreadable";
  const factory = reports.find((row) => row.id === "kernelFactory");
  if (factory?.status === "verified") {
    try {
      const result = await rpc.request("eth_call", [
        { to: factory.address, data: encodeKernelV4FactoryImplementationRead() },
        block,
      ]);
      if (typeof result !== "string" || !/^0x0{24}[0-9a-fA-F]{40}$/u.test(result))
        throw new Error();
      const [address] = decodeAbiParameters([{ type: "address" }], result as Hex);
      factoryBinding =
        address.toLowerCase() === KERNEL_V4_UUPS_IMPLEMENTATION_V07 ? "verified" : "mismatch";
    } catch {}
  }
  return {
    ...base,
    observedChainId,
    blockNumber: BigInt(block).toString(),
    ready:
      factoryBinding === "verified" &&
      reports
        .filter((row) => row.required)
        .every((row) => row.status === "verified" || row.status === "present"),
    error: null,
    factoryBinding,
    components: reports,
  };
}
