import { expect, it } from "vitest";
import { membershipContext, matchingMembership } from "../src/membership-handoff.js";

const account = `0x${"11".repeat(20)}`;
const fragment = (origin = "https://keyline.taek.tech") =>
  `#${new URLSearchParams({
    return_origin: origin,
    state: "a".repeat(43),
    account,
    label: "Colleague",
  })}`;

it("binds a handoff to its exact account and return origin without giving it authority", () => {
  const context = membershipContext(fragment())!;
  expect(context.origin).toBe("https://keyline.taek.tech");
  expect(matchingMembership(context, { address: account })).toBe(true);
  expect(matchingMembership(context, { address: `0x${"22".repeat(20)}` })).toBe(false);
  expect(membershipContext(fragment("javascript:alert(1)"))).toBeNull();
  expect(membershipContext(fragment("https://keyline.taek.tech/redirect"))).toBeNull();
  expect(membershipContext(fragment("http://evil.example"))).toBeNull();
  expect(membershipContext(fragment().replace("state=", "other="))).toBeNull();
});
