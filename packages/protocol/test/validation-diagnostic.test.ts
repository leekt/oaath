import { describe, expect, it } from "vitest";
import {
  captureValidationGasDiagnostic,
  readValidationGasDiagnostic,
  validationGasDiagnosticMessage,
} from "../src/index.js";

const diagnostic = { kind: "validation_gas_likely_insufficient", verificationGasLimit: "2000000" };

describe("closed validation diagnostic", () => {
  it("captures only the display kind and canonical gas limit", () => {
    const captured = captureValidationGasDiagnostic(diagnostic);
    expect(captured).toEqual(diagnostic);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(validationGasDiagnosticMessage(captured!)).toBe(
      "likely validation out-of-gas (verificationGasLimit=2000000)",
    );
  });

  it.each([
    null,
    {},
    { ...diagnostic, raw: "provider material" },
    { ...diagnostic, kind: "retry_allowed" },
    ...["01", "-1", "0x10", "1.1", (1n << 120n).toString(), 2_000_000].map(
      (verificationGasLimit) => ({ ...diagnostic, verificationGasLimit }),
    ),
  ])("discards malformed or expanded diagnostics", (value) => {
    expect(captureValidationGasDiagnostic(value)).toBeNull();
  });

  it("never reads a diagnostic accessor or inherits a provider value", () => {
    let reads = 0;
    expect(
      readValidationGasDiagnostic({
        get diagnostic() {
          reads++;
          return diagnostic;
        },
      }),
    ).toBeNull();
    expect(readValidationGasDiagnostic(Object.create({ diagnostic }))).toBeNull();
    expect(reads).toBe(0);
    expect(readValidationGasDiagnostic({ diagnostic })).toEqual(diagnostic);
  });
});
