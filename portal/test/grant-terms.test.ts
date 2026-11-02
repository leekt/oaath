import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { GrantTerms } from "../src/GrantReview.js";

const terms = (calls: readonly unknown[]) =>
  renderToStaticMarkup(
    createElement(GrantTerms, {
      credential: { kind: "ecdsa", address: `0x${"44".repeat(20)}` } as never,
      policy: {
        version: "oaath.grant-policy/v1",
        calls,
        validAfter: 1_000,
        validUntil: 1_599,
        perChainOperationLimit: null,
      } as never,
      chains: [421614],
      expiresAt: 1_600,
    }),
  );

it("warns that a sudo grant has full control of the account for its window", () => {
  expect(terms([])).toContain(
    "Full control of this account for 10 minutes: this app can make any transaction, including changing the account&#x27;s owner.",
  );
  const call = { target: `0x${"aa".repeat(20)}`, selector: "0xa9059cbb", valueLimit: "0" };
  expect(terms([{ ...call, argumentEquals: [] }])).not.toContain("Full control");
});
