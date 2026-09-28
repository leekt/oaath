/** Explicit auto preference, resolved before any quote, signature or submission. */
export function selectAutoSigner(ownerAvailable: boolean, singleUserOperation: boolean) {
  if (ownerAvailable && singleUserOperation)
    return Object.freeze({
      signer: "owner" as const,
      reason: "owner_auto_single_operation" as const,
    });
  return Object.freeze({
    signer: "session" as const,
    reason: ownerAvailable
      ? ("session_auto_multiple_operations" as const)
      : ("session_auto_owner_unavailable" as const),
  });
}
