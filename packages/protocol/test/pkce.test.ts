import { describe, expect, it } from "vitest";
import { deriveCodeChallenge, OaathProtocolError } from "../src/index.js";

// Public RFC 7636 Appendix B vector, not an application credential.
const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("PKCE S256 challenge", () => {
  it("derives the RFC 7636 challenge", () => {
    expect(deriveCodeChallenge(codeVerifier)).toBe(codeChallenge);
  });

  it("rejects invalid verifiers with the existing structured code", () => {
    for (const value of ["a".repeat(42), "a".repeat(129), `${codeVerifier}!`, 7, null]) {
      try {
        deriveCodeChallenge(value);
      } catch (error) {
        expect(error).toBeInstanceOf(OaathProtocolError);
        expect(error).toMatchObject({ code: "authorization_code_verifier_mismatch" });
        continue;
      }
      throw new Error("Expected authorization_code_verifier_mismatch");
    }
  });
});
