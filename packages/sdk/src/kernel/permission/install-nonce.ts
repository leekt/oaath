/**
 * Owns the install nonce selected for a canonical permission request.
 *
 * @author taek <leekt216@gmail.com>
 */
import { inputInvalid, isHash } from "../internal.js";

/**
 * Derives Kernel's uint192 install key from the first 192 bits of
 * hashPermissionRequest(request), with uint64 sequence zero. The same request
 * recreates the same nonce without an allocation store; separate requests do
 * not share the default key's install history.
 *
 * This requires an unused key and Kernel's global validNonceFrom() to be zero
 * on each destination chain. It does not reconcile an account whose owner has
 * advanced that global minimum, reset consumed approvals, or allocate an
 * EntryPoint operation nonce. Returns a decimal uint256.
 */
export function kernelPermissionInstallNonce(requestHash: `0x${string}`): string {
  if (!isHash(requestHash)) return inputInvalid("permission request hash is invalid");
  return ((BigInt(requestHash) >> 64n) << 64n).toString(10);
}
