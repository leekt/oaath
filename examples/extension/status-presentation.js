/** Public EIP-5792 status formatting for the extension's read-only status UI. */

const STATUS_LABELS = Object.freeze({
  100: "pending",
  200: "confirmed",
  400: "failed before inclusion",
  500: "reverted",
});
const STATUS_PRESENTATION_PREFIX = "wallet-call-status:";

export async function showWalletCallStatus(extension, origin, status) {
  const token = crypto.randomUUID();
  const key = `${STATUS_PRESENTATION_PREFIX}${token}`;
  await extension.storage.session.set({ [key]: { origin, status } });
  try {
    await extension.tabs.create({
      active: true,
      url: extension.runtime.getURL(`status.html#${encodeURIComponent(token)}`),
    });
  } catch (error) {
    await extension.storage.session.remove(key).catch(() => undefined);
    throw error;
  }
}

export function formatWalletCallStatus(record) {
  const status = record?.status;
  const label = STATUS_LABELS[status?.status];
  if (
    typeof record?.origin !== "string" ||
    typeof status?.id !== "string" ||
    typeof status?.chainId !== "string" ||
    label === undefined
  ) {
    throw new Error("wallet call status is unavailable");
  }

  const lines = [
    `origin   ${record.origin}`,
    `bundle   ${status.id}`,
    `chain    ${status.chainId}`,
    `atomic   ${status.atomic === true ? "yes" : "no"}`,
    `status   ${status.status} ${label}`,
  ];
  const receipt = Array.isArray(status.receipts) ? status.receipts[0] : undefined;
  if (receipt) {
    lines.push(
      `tx       ${receipt.transactionHash}`,
      `block    ${receipt.blockNumber}`,
      `result   ${receipt.status === "0x1" ? "success" : "reverted"}`,
    );
  }
  return lines.join("\n");
}
