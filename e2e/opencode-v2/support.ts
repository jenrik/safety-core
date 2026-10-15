import { resolve } from "node:path";

import { Effect } from "effect";

export const root = requiredEnvironment("SAFETY_CORE_E2E_ROOT");
export const plugin = requiredEnvironment("SAFETY_CORE_OPENCODE_V2_PLUGIN");
export const executable = process.env.SAFETY_CORE_OPENCODE_V2_COMMAND ?? "opencode2";

export function configHome(fixture: string): string {
  return resolve(root, "e2e/opencode-v2/fixtures", fixture);
}

export function isolatedEnvironment(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    ANTHROPIC_API_KEY: "",
    ANTHROPIC_BASE_URL: "",
    OPENAI_API_KEY: "",
    OPENAI_BASE_URL: "",
    ...overrides,
  };
}

export function poll<A, E, R>(effect: Effect.Effect<A | undefined, E, R>, description: string) {
  return Effect.gen(function* () {
    while (true) {
      const value = yield* effect;
      if (value !== undefined) return value;
      yield* Effect.sleep(50);
    }
  }).pipe(
    Effect.timeoutOrElse({
      duration: 10_000,
      orElse: () => Effect.fail(new Error(`timed out waiting for ${description}`)),
    }),
  );
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined) throw new Error(`Run this scenario through scripts/test-opencode-v2-e2e.ts (${name} is missing)`);
  return value;
}
