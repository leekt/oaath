/**
 * Lets the examples run from this repository without a build step.
 *
 * The examples import `@oaath/protocol` and `@oaath/sdk` by their published
 * specifiers, exactly as an adopter does. Inside this workspace
 * this hook opts into the `oaath-source` condition for TypeScript sources, which Node runs
 * by stripping types — except that the sources import each other with `.js`
 * specifiers, which is what the published build emits. This hook maps that one
 * gap.
 *
 * An adopter needs none of this: `bun add @oaath/sdk` installs the built
 * artifacts and `node app.mjs` resolves them directly. Nothing below changes
 * which specifiers the examples are allowed to use.
 *
 * @author taek <leekt216@gmail.com>
 */

import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, next) {
    const sourceContext = {
      ...context,
      conditions: [...context.conditions, "oaath-source"],
    };
    try {
      return next(specifier, sourceContext);
    } catch (error) {
      if (specifier.endsWith(".js")) return next(`${specifier.slice(0, -3)}.ts`, sourceContext);
      throw error;
    }
  },
});
