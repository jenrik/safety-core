import { beforeAll, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The per-policy suites are colocated with their policies in `.safety-core/`, which
// `bun test` discovery skips because it is a dot directory. Importing them here is what
// makes them run under `bun test` and the pre-commit `bun run test` hook, so a new
// project-local `<policy>.test.ts` must be added to this list. Note that
// `safety-core test .safety-core/<policy>.test.ts` does not work: the runner looks for a
// sibling `<stem>.json`/`<stem>.mjs`, not the `<stem>.policy.json` naming used here.
import "../.safety-core/bun-run.test.ts";
import "../.safety-core/bun-test.test.ts";

import { analyzeBashWithPolicies, completePolicyInitialEnvironment, initBundledBashParser } from "../src/index.ts";
import { type LoadedPolicySet, loadPolicySources } from "../src/policy/load.ts";

const root = fileURLToPath(new URL("..", import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(root, ".safety-core/config.json"), "utf8")) as {
  readonly version: number;
  readonly policies: readonly string[];
};

let loaded: LoadedPolicySet | undefined;

async function policySet(): Promise<LoadedPolicySet> {
  if (loaded === undefined)
    loaded = await loadPolicySources(
      manifest.policies.map((reference) => ({ path: resolve(root, reference), scope: "project" as const })),
    );
  return loaded;
}

function analyze(source: string) {
  return analyzeBashWithPolicies({
    source,
    policies: loaded!.policies,
    initialEnvironment: completePolicyInitialEnvironment({ PATH: "/usr/bin:/bin" }),
    cwd: root,
  });
}

beforeAll(async () => {
  await initBundledBashParser();
  await policySet();
});

test("project manifest selects exactly the two co-located bun policies", async () => {
  expect(manifest.version).toBe(1);
  expect(manifest.policies).toEqual([".safety-core/bun-run.policy.json", ".safety-core/bun-test.policy.json"]);
  for (const reference of manifest.policies) expect(existsSync(resolve(root, reference)), reference).toBe(true);
  const set = await policySet();
  expect(set.sources.map((source) => source.scope)).toEqual(["project", "project"]);
  expect(set.policies).toHaveLength(2);
});

test("the project dev loop is covered end to end", () => {
  for (const source of [
    "bun run build:native-packages",
    "bun run test",
    "bun run typescheck",
    "bun test",
    "bun test tests/example.test.ts",
    "bun run build:native-packages && bun test",
    "bun run build:native-packages && bun test tests/example.test.ts",
  ])
    expect(analyze(source).decision, source).toBe("allow");
});

test("unreviewed scripts, escaping paths, excluded flags, and any `--` stay deferred", () => {
  for (const source of [
    "bun run lint",
    "bun run ./scripts/build-native-node-packages.ts",
    "bun run test tests/example.test.ts",
    "bun test /tmp/evil.test.ts",
    "bun test ../evil.test.ts",
    "bun test --preload=./setup.ts",
    "bun test --watch",
    "bun test -u",
    "bun test --",
    "bun test -- tests/example.test.ts",
    "bun test -- --timeout /tmp/evil.test.ts",
    "bun test -t -- --seed /tmp/evil.test.ts",
    "bun test --timeout -- tests/example.test.ts",
    "bun install",
    "bun typescheck",
  ])
    expect(analyze(source).decision, source).toBe("defer");
});
