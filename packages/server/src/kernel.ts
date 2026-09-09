/**
 * Kernel owner-operation execution for deployment workers. Reuses SDK operation
 * state, submission and observation; imports no Node/PG driver. The relay root
 * remains independent of the runtime graph. Approval is separate from execution.
 */

export type {
  OwnerPhoneRevocationExecutor,
  OwnerPhoneRevocationExecutorInput,
} from "./revocation/executor.js";
export { createOwnerPhoneRevocationExecutor } from "./revocation/executor.js";
