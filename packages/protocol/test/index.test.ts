import { expect, test } from "vitest";
import { OAATH_PROTOCOL } from "../src/index.js";

test("protocol package identifies itself", () => {
  expect(OAATH_PROTOCOL).toBe("@oaath/protocol");
});
