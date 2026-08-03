import { expect, test } from "vitest";
import { OAATH_TESTING } from "../src/index.js";

test("testing package identifies itself", () => {
  expect(OAATH_TESTING).toBe("@oaath/testing");
});
