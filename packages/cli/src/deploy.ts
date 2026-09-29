import { kernelDeployment } from "@oaath/sdk/kernel";
import { createWalletClient, custom, type Hex, keccak256, type PrivateKeyAccount } from "viem";
import { type DoctorReport, doctor } from "./doctor.js";
import type { DeploymentJournal, DeploymentRecord } from "./journal.js";
import { type Component, components } from "./manifest.js";
import type { RpcReader } from "./rpc.js";

export class DeploymentError extends Error {
  constructor(
    readonly code:
      | "deployment_prerequisite_missing"
      | "deployment_evidence_invalid"
      | "deployment_key_required"
      | "deployment_key_invalid"
      | "deployment_transaction_invalid"
      | "deployment_reverted"
      | "deployment_journal_conflict",
  ) {
    super(code);
  }
}

export interface DeploymentResult {
  readonly version: "oaath.runtime-deployment/v1";
  readonly chainId: number;
  readonly status: "planned" | "ready" | "pending";
  readonly missing: readonly string[];
  readonly transactionHash: Hex | null;
  readonly readiness: DoctorReport;
}

/** The core ECDSA set plus the passkey-session modules; never other optional rows. */
function deploys(row: Readonly<{ required: boolean; passkeySession: boolean }>): boolean {
  return row.required || row.passkeySession;
}

function validateReadiness(report: DoctorReport): void {
  if (
    report.error ||
    report.components.some(
      (row) => deploys(row) && (row.status === "mismatch" || row.status === "unreadable"),
    )
  )
    throw new DeploymentError("deployment_evidence_invalid");
  for (const id of ["entryPoint", "create2Deployer"])
    if (report.components.find((row) => row.id === id)?.status !== "verified")
      throw new DeploymentError("deployment_prerequisite_missing");
  if (
    report.components.find((row) => row.id === "kernelFactory")?.status === "verified" &&
    report.factoryBinding !== "verified"
  )
    throw new DeploymentError("deployment_evidence_invalid");
}

function recordObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new DeploymentError("deployment_evidence_invalid");
  return value as Record<string, unknown>;
}

function quantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(value) || value.length > 66)
    throw new DeploymentError("deployment_evidence_invalid");
  return BigInt(value);
}

function hash(value: unknown): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value))
    throw new DeploymentError("deployment_evidence_invalid");
  return value as Hex;
}

/** Only canonical finalized evidence releases an attempted transaction's lane. */
async function observe(
  record: DeploymentRecord,
  manifest: readonly Component[],
  rpc: RpcReader,
  journal: DeploymentJournal,
  attempts: number,
): Promise<boolean> {
  const component = manifest.find((row) => row.id === record.component);
  if (
    !component?.deploymentInput ||
    record.address !== component.address ||
    record.inputHash !== keccak256(component.deploymentInput)
  )
    throw new DeploymentError("deployment_journal_conflict");
  if (record.state === "confirmed") return true;
  if (record.state === "reverted") throw new DeploymentError("deployment_reverted");
  const deployer = kernelDeployment({ chainId: record.chainId }).create2Deployer;
  for (let count = 0; count < attempts; count += 1) {
    if (count > 0) await new Promise((resolve) => setTimeout(resolve, 1_000));
    try {
      const value = await rpc.request("eth_getTransactionReceipt", [record.transactionHash]);
      if (value === null) continue;
      const receipt = recordObject(value);
      if (
        hash(receipt.transactionHash) !== record.transactionHash ||
        receipt.from !== record.wallet ||
        receipt.to !== deployer ||
        (receipt.status !== "0x1" && receipt.status !== "0x0")
      )
        throw new DeploymentError("deployment_evidence_invalid");
      const blockNumber = quantity(receipt.blockNumber);
      const blockHash = hash(receipt.blockHash);
      const finalized = recordObject(
        await rpc.request("eth_getBlockByNumber", ["finalized", false]),
      );
      const finalizedHash = hash(finalized.hash);
      if (quantity(finalized.number) < blockNumber) continue;
      const finalizedCanonical = recordObject(
        await rpc.request("eth_getBlockByNumber", [finalized.number, false]),
      );
      if (
        hash(finalizedCanonical.hash) !== finalizedHash ||
        quantity(finalizedCanonical.number) !== quantity(finalized.number)
      )
        throw new DeploymentError("deployment_evidence_invalid");
      const canonical = recordObject(
        await rpc.request("eth_getBlockByNumber", [receipt.blockNumber, false]),
      );
      if (hash(canonical.hash) !== blockHash || quantity(canonical.number) !== blockNumber)
        throw new DeploymentError("deployment_evidence_invalid");
      const transaction = recordObject(
        await rpc.request("eth_getTransactionByHash", [record.transactionHash]),
      );
      if (
        hash(transaction.hash) !== record.transactionHash ||
        transaction.from !== record.wallet ||
        transaction.to !== deployer ||
        transaction.input !== component.deploymentInput ||
        quantity(transaction.nonce) !== BigInt(record.nonce) ||
        quantity(transaction.value) !== 0n ||
        quantity(transaction.chainId) !== BigInt(record.chainId) ||
        hash(transaction.blockHash) !== blockHash ||
        quantity(transaction.blockNumber) !== blockNumber
      )
        throw new DeploymentError("deployment_evidence_invalid");
      if (receipt.status === "0x0") {
        journal.finish(record, "reverted");
        throw new DeploymentError("deployment_reverted");
      }
      const code = await rpc.request("eth_getCode", [component.address, receipt.blockNumber]);
      if (
        typeof code !== "string" ||
        !/^0x(?:[0-9a-f]{2})+$/u.test(code) ||
        code.length > 131_074 ||
        (component.runtimeCodeHash !== null && keccak256(code as Hex) !== component.runtimeCodeHash)
      )
        throw new DeploymentError("deployment_evidence_invalid");
      journal.finish(record, "confirmed");
      return true;
    } catch (error) {
      if (error instanceof DeploymentError) throw error;
      // An unavailable read is never absence or authorization to sign/send again.
      return false;
    }
  }
  return false;
}

export async function deployRuntime(input: {
  chainId: number;
  rpc: RpcReader;
  journal: DeploymentJournal;
  account: () => PrivateKeyAccount;
  dryRun?: boolean;
  /** Test-only clock bound; the CLI always uses the default. */
  observationAttempts?: number;
}): Promise<DeploymentResult> {
  const { chainId, rpc, journal } = input;
  const manifest = components(chainId);
  const deployer = kernelDeployment({ chainId }).create2Deployer;
  let report = await doctor(chainId, rpc);
  validateReadiness(report);
  const result = (
    status: DeploymentResult["status"],
    transactionHash: Hex | null = null,
  ): DeploymentResult => ({
    version: "oaath.runtime-deployment/v1",
    chainId,
    status,
    missing: report.components
      .filter((row) => deploys(row) && row.status === "missing")
      .map((row) => row.id),
    transactionHash,
    readiness: report,
  });
  if (input.dryRun) return result("planned");
  const pending = journal.pending(chainId);
  if (pending && !(await observe(pending, manifest, rpc, journal, input.observationAttempts ?? 30)))
    return result("pending", pending.transactionHash);
  const wallet = () =>
    createWalletClient({
      account: input.account(),
      transport: custom(
        {
          request: ({ method, params }) =>
            rpc.request(method, params as readonly unknown[] | undefined),
        },
        { retryCount: 0 },
      ),
    });
  for (const component of manifest.filter((row) => deploys(row) && row.deploymentInput)) {
    // Capture current code again after recovering another process's transaction.
    const code = await rpc.request("eth_getCode", [component.address, "latest"]);
    if (code !== "0x") {
      if (
        typeof code !== "string" ||
        !/^0x(?:[0-9a-f]{2})+$/u.test(code) ||
        (component.runtimeCodeHash !== null && keccak256(code as Hex) !== component.runtimeCodeHash)
      )
        throw new DeploymentError("deployment_evidence_invalid");
      continue;
    }
    const retained = journal.get(chainId, component.id);
    if (retained) {
      if (retained.state === "confirmed") throw new DeploymentError("deployment_evidence_invalid");
      if (!(await observe(retained, manifest, rpc, journal, input.observationAttempts ?? 30)))
        return result("pending", retained.transactionHash);
      continue;
    }
    const client = wallet();
    const request = await client.prepareTransactionRequest({
      account: client.account,
      chain: null,
      to: deployer,
      data: component.deploymentInput as Hex,
      value: 0n,
    });
    if (
      request.chainId !== chainId ||
      !Number.isSafeInteger(request.nonce) ||
      request.nonce < 0 ||
      request.gas <= 0n ||
      request.gas > 10_000_000n
    )
      throw new DeploymentError("deployment_transaction_invalid");
    const transaction = {
      chainId,
      nonce: request.nonce,
      gas: request.gas,
      to: deployer,
      data: component.deploymentInput as Hex,
      value: 0n,
    };
    let signed: Hex;
    if (
      request.type === "eip1559" &&
      typeof request.maxFeePerGas === "bigint" &&
      typeof request.maxPriorityFeePerGas === "bigint"
    )
      signed = await client.account.signTransaction({
        ...transaction,
        type: "eip1559",
        maxFeePerGas: request.maxFeePerGas,
        maxPriorityFeePerGas: request.maxPriorityFeePerGas,
      });
    else if (request.type === "legacy" && typeof request.gasPrice === "bigint")
      signed = await client.account.signTransaction({
        ...transaction,
        type: "legacy",
        gasPrice: request.gasPrice,
      });
    else throw new DeploymentError("deployment_transaction_invalid");
    const attempt: DeploymentRecord = {
      chainId,
      component: component.id,
      address: component.address,
      wallet: client.account.address.toLowerCase() as Hex,
      inputHash: keccak256(component.deploymentInput as Hex),
      transactionHash: keccak256(signed),
      nonce: request.nonce,
      state: "attempted",
    };
    const reservation = journal.reserve(attempt);
    if (reservation.inserted) {
      try {
        await rpc.request("eth_sendRawTransaction", [signed]);
      } catch {
        /* Retain the exact hash and only observe, even after a lost reply. */
      }
    }
    if (
      !(await observe(reservation.record, manifest, rpc, journal, input.observationAttempts ?? 30))
    )
      return result("pending", reservation.record.transactionHash);
    if (reservation.record.component !== component.id) {
      // A concurrent command owns the chain lane. Start a fresh invocation after
      // observing it; never broadcast the now-stale signed transaction above.
      report = await doctor(chainId, rpc);
      return result(report.ready && report.passkeySessionsReady ? "ready" : "planned");
    }
  }
  report = await doctor(chainId, rpc);
  validateReadiness(report);
  if (!report.ready || !report.passkeySessionsReady)
    throw new DeploymentError("deployment_evidence_invalid");
  return result("ready");
}
