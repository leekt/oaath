/**
 * Lets the examples run from this repository without a build step.
 *
 * The examples import `@oaath/protocol`, `@oaath/sdk`, and `@oaath/server` by
 * their published specifiers, exactly as an adopter does. Inside this workspace
 * those specifiers resolve to the packages' TypeScript sources, which Node runs
 * by stripping types — except that the sources import each other with `.js`
 * specifiers, which is what the published build emits. This hook maps that one
 * gap.
 *
 * An adopter needs none of this: `pnpm add @oaath/sdk` installs the built
 * artifacts and `node app.mjs` resolves them directly. Nothing below changes
 * which specifiers the examples are allowed to use.
 *
 * @author taek <leekt216@gmail.com>
 */

import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, next) {
    try {
      return next(specifier, context);
    } catch (error) {
      if (specifier.endsWith(".js")) return next(`${specifier.slice(0, -3)}.ts`, context);
      throw error;
    }
  },
});
