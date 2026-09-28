import { exactRecord } from "./internal/exact-record.js";

/** Display-only evidence. It never authorizes a retry, fallback, or gas change. */
export interface ValidationGasDiagnostic {
  readonly kind: "validation_gas_likely_insufficient";
  readonly verificationGasLimit: string;
}

/** A closed projection; malformed or extra data is discarded in full. */
export function captureValidationGasDiagnostic(
  value: unknown,
): Readonly<ValidationGasDiagnostic> | null {
  try {
    const record = exactRecord(
      value,
      ["kind", "verificationGasLimit"],
      "validation diagnostic",
      new WeakSet(),
      () => {
        throw new Error("invalid diagnostic");
      },
    );
    if (
      record.kind !== "validation_gas_likely_insufficient" ||
      typeof record.verificationGasLimit !== "string" ||
      !/^(?:0|[1-9][0-9]{0,36})$/u.test(record.verificationGasLimit) ||
      BigInt(record.verificationGasLimit) >= 1n << 120n
    )
      return null;
    return Object.freeze({ kind: record.kind, verificationGasLimit: record.verificationGasLimit });
  } catch {
    return null;
  }
}

/** Read only an own data property, never an error message or accessor. */
export function readValidationGasDiagnostic(
  error: unknown,
): Readonly<ValidationGasDiagnostic> | null {
  if (!error || typeof error !== "object") return null;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, "diagnostic");
    return descriptor && "value" in descriptor
      ? captureValidationGasDiagnostic(descriptor.value)
      : null;
  } catch {
    return null;
  }
}

/** The one display message for a captured diagnostic, independent of provider prose. */
export function validationGasDiagnosticMessage(
  diagnostic: Readonly<ValidationGasDiagnostic>,
): string {
  return `likely validation out-of-gas (verificationGasLimit=${diagnostic.verificationGasLimit})`;
}
