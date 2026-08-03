import { expect, test } from "vitest";
import { OAATH_SERVER } from "../src/index.js";

test("server package identifies itself", () => {
  expect(OAATH_SERVER).toBe("@oaath/server");
});
