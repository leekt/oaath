/**
 * Types the repo-owned live-provider deny list so TypeScript consumers import
 * the one list instead of keeping a copy that silently goes stale. The list
 * itself stays in live-provider-environment.mjs, which Node runs directly as the
 * vitest globalSetup.
 *
 * ponytail: hand-written, so nothing forces it to match the implementation's
 * signature; the deny list itself is covered by
 * packages/sdk/test/live-provider-environment.test.mjs. Generate it from the
 * source if this function ever grows a second parameter.
 *
 * @author taek <leekt216@gmail.com>
 */
export declare function scrubLiveProviderEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): Record<string, string | undefined>;
