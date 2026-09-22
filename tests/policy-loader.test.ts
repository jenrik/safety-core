import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PolicyStartupError,
  loadGlobalPolicyConfig,
  resolveSessionPolicyConfig,
} from "../src/policy/config.ts";
import { loadPolicySet } from "../src/policy/load.ts";

function fixtureDirectory(): string {
  return mkdtempSync(join(tmpdir(), "safety-core-policy-loader-"));
}

function writeConfig(home: string, policies: readonly string[]): void {
  const directory = join(home, "safety-core");
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "config.json"), JSON.stringify({
    version: 1,
    policies,
    projectPolicies: { mode: "disabled" },
    bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 5, maxWorkItems: 4 },
  }));
}

function frozenDefinition(layer: "guard" | "permission" = "permission"): object {
  return Object.freeze({
    apiVersion: 1,
    layer,
    select: Object.freeze([{ kind: "invocation" }]),
    evaluate: () => ({ kind: "ignore" as const }),
  });
}

function resolvedConfig(home: string, policies: readonly string[]) {
  writeConfig(home, policies);
  return resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), home);
}

describe("trusted code policy source loading", () => {
  test("uses canonical paths as identity, collapsing aliases but not identical source bytes", async () => {
    const home = fixtureDirectory();
    const policyDirectory = join(home, "policies");
    mkdirSync(policyDirectory);
    const first = join(policyDirectory, "first.policy.mjs");
    const alias = join(policyDirectory, "first-alias.policy.mjs");
    const second = join(policyDirectory, "second.policy.mjs");
    writeFileSync(first, "export default {};\n");
    writeFileSync(second, "export default {};\n");
    symlinkSync(first, alias);

    const loaded = await loadPolicySet(resolvedConfig(home, [first, alias, second]), {
      importCodePolicy: () => ({ default: frozenDefinition() }),
    });
    const [realFirst, realSecond] = [realpathSync(first), realpathSync(second)];

    expect(loaded.sources.map((source) => source.canonicalPath)).toEqual([realFirst, realSecond]);
    expect(loaded.sources[0]!.sha256).toBe(loaded.sources[1]!.sha256);
    expect(loaded.policies).toHaveLength(2);
    expect(Object.isFrozen(loaded)).toBeTrue();
    expect(Object.isFrozen(loaded.sources)).toBeTrue();
    expect(Object.isFrozen(loaded.policies)).toBeTrue();
  });

  test("loads a complete frozen api-versioned definition and attaches provenance", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "read.policy.mjs");
    writeFileSync(policy, "export default {};\n");
    const loaded = await loadPolicySet(resolvedConfig(home, [policy]), {
      importCodePolicy: (url) => {
        expect(url).toBe(new URL(`file://${realpathSync(policy)}`).href);
        return { default: frozenDefinition("guard") };
      },
    });

    expect(loaded.policies[0]).toMatchObject({
      source: { canonicalPath: realpathSync(policy) },
      layer: "guard",
      select: [{ kind: "invocation" }],
    });
    expect(Object.isFrozen(loaded.policies[0]!)).toBeTrue();
    expect(Object.isFrozen(loaded.policies[0]!.source)).toBeTrue();
  });

  test("rejects relative runtime imports before executing the module", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "relative.policy.mjs");
    writeFileSync(policy, "import './other.mjs'; export default {};\n");
    let imported = false;

    await expect(loadPolicySet(resolvedConfig(home, [policy]), {
      importCodePolicy: () => {
        imported = true;
        return { default: frozenDefinition() };
      },
    })).rejects.toBeInstanceOf(PolicyStartupError);
    expect(imported).toBeFalse();
  });

  test("property: 1,024 commented and template-literal relative imports are rejected before initialization", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "commented-relative.policy.mjs");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const source = seed % 3 === 0
        ? `import /* note ${seed} */ "./helper.mjs"; export default {};\n`
        : seed % 3 === 1
          ? `await import(/* note ${seed} */ \`./helper.mjs\`); export default {};\n`
          : `await import(// note ${seed}\n "./helper.mjs"); export default {};\n`;
      writeFileSync(policy, source);
      let imported = false;
      await expect(loadPolicySet(resolved, {
        importCodePolicy: () => {
          imported = true;
          return { default: frozenDefinition() };
        },
      }), `seed ${seed}`).rejects.toBeInstanceOf(PolicyStartupError);
      expect(imported, `seed ${seed}`).toBeFalse();
    }
  });

  test("scans module specifiers without mistaking policy strings for imports", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "message.policy.mjs");
    writeFileSync(policy, "const message = \"import value from './example'\"; export default {};\n");

    const loaded = await loadPolicySet(resolvedConfig(home, [policy]), {
      importCodePolicy: () => ({ default: frozenDefinition() }),
    });
    expect(loaded.policies).toHaveLength(1);
  });

  test("does not mistake comments within a non-relative import for another module specifier", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "commented-absolute.policy.mjs");
    writeFileSync(policy, "import /* from './not-a-source.mjs' */ 'node:fs'; export default {};\n");

    const loaded = await loadPolicySet(resolvedConfig(home, [policy]), {
      importCodePolicy: () => ({ default: frozenDefinition() }),
    });
    expect(loaded.policies).toHaveLength(1);
  });

  test("turns malformed exports and import failures into source-positioned fatal errors", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "broken.policy.mjs");
    writeFileSync(policy, "export default {};\n");
    const resolved = resolvedConfig(home, [policy]);

    await expect(loadPolicySet(resolved, { importCodePolicy: () => ({ default: { apiVersion: 1 } }) })).rejects.toThrow(realpathSync(policy));
    await expect(loadPolicySet(resolved, { importCodePolicy: () => { throw new Error("initialization failed"); } })).rejects.toThrow("initialization failed");
    await expect(loadPolicySet(resolved, { importCodePolicy: () => ({ default: Object.freeze({ ...frozenDefinition(), apiVersion: 2 }) }) })).rejects.toThrow("apiVersion");
  });

  test("property: 1,024 malformed import escapes fail as source-positioned startup errors", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "malformed-escape.policy.mjs");
    const resolved = resolvedConfig(home, [policy]);
    const malformed = ["\\xGG", "\\x0G", "\\uGGGG", "\\u{GG}"];

    for (let seed = 0; seed < 1_024; seed++) {
      writeFileSync(policy, `import "${malformed[seed % malformed.length]}"; export default {};\n`);
      let imported = false;
      try {
        await loadPolicySet(resolved, {
          importCodePolicy: () => {
            imported = true;
            return { default: frozenDefinition() };
          },
        });
        throw new Error(`Expected seed ${seed} to reject`);
      } catch (error) {
        expect(error, `seed ${seed}`).toBeInstanceOf(PolicyStartupError);
        expect((error as PolicyStartupError).sourcePath, `seed ${seed}`).toBe(realpathSync(policy));
      }
      expect(imported, `seed ${seed}`).toBeFalse();
    }
  });

  test("property: 1,024 loaded selector trees are deeply immutable", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "immutable.policy.mjs");
    writeFileSync(policy, "export default {};\n");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const definition = Object.freeze({
        apiVersion: 1,
        layer: "permission" as const,
        select: [{ kind: "invocation", nested: { seed } }],
        evaluate: () => ({ kind: "ignore" as const }),
      });
      const loaded = await loadPolicySet(resolved, { importCodePolicy: () => ({ default: definition }) });
      const selector = loaded.policies[0]!.select[0] as { readonly nested: { readonly seed: number } };

      expect(Object.isFrozen(selector), `seed ${seed}`).toBeTrue();
      expect(Object.isFrozen(selector.nested), `seed ${seed}`).toBeTrue();
      expect(() => { (selector.nested as { seed: number }).seed = -1; }, `seed ${seed}`).toThrow();
    }
  });

  test("property: 1,024 selector collections are rejected instead of exposed as mutable loaded state", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "collection-selector.policy.mjs");
    writeFileSync(policy, "export default {};\n");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const collection = seed % 2 === 0 ? new Map([["seed", seed]]) : new Set([seed]);
      const definition = Object.freeze({
        apiVersion: 1,
        layer: "permission" as const,
        select: [{ kind: "invocation", nested: collection }],
        evaluate: () => ({ kind: "ignore" as const }),
      });
      await expect(loadPolicySet(resolved, { importCodePolicy: () => ({ default: definition }) }), `seed ${seed}`)
        .rejects.toBeInstanceOf(PolicyStartupError);
    }
  });

  test("property: 1,024 relative imports inside template substitutions are rejected before initialization", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "template-substitution.policy.mjs");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const source = seed % 2 === 0
        ? `const value = \`\${await import("./helper.mjs")}\`; export default {};\n`
        : `const value = \`\${await import(/* ${seed} */ "./helper.mjs")}\`; export default {};\n`;
      writeFileSync(policy, source);
      let imported = false;
      await expect(loadPolicySet(resolved, {
        importCodePolicy: () => {
          imported = true;
          return { default: frozenDefinition() };
        },
      }), `seed ${seed}`).rejects.toBeInstanceOf(PolicyStartupError);
      expect(imported, `seed ${seed}`).toBeFalse();
    }
  });

  test("property: 1,024 regex braces do not terminate template substitutions before relative imports", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "template-regex.policy.mjs");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const expression = seed % 3 === 0 ? "/}/.test(\"x\")"
        : seed % 3 === 1 ? "/[}]/.test(\"x\")"
          : "/\\}/.test(\"x\")";
      writeFileSync(policy, `const value = \`\${${expression} ? await import("./helper.mjs") : ""}\`; export default {};\n`);
      let imported = false;
      await expect(loadPolicySet(resolved, {
        importCodePolicy: () => {
          imported = true;
          return { default: frozenDefinition() };
        },
      }), `seed ${seed}`).rejects.toBeInstanceOf(PolicyStartupError);
      expect(imported, `seed ${seed}`).toBeFalse();
    }
  });

  test("property: 1,024 postfix updates in template substitutions permit following division", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "template-postfix-division.policy.mjs");
    const resolved = resolvedConfig(home, [policy]);
    const spacing = ["", " ", "\t", "\n"];

    for (let seed = 0; seed < 1_024; seed++) {
      const update = seed % 2 === 0 ? "++" : "--";
      writeFileSync(policy, `let counter = 4; const value = \`\${counter${update}${spacing[seed % spacing.length]!}/ 2}\`; export default {};\n`);
      let imported = false;
      const loaded = await loadPolicySet(resolved, {
        importCodePolicy: () => {
          imported = true;
          return { default: frozenDefinition() };
        },
      });
      expect(loaded.policies, `seed ${seed}`).toHaveLength(1);
      expect(imported, `seed ${seed}`).toBeTrue();
    }
  });

  test("property: 1,024 hidden, symbol, and inherited definition fields are rejected", async () => {
    const home = fixtureDirectory();
    const policy = join(home, "closed-schema.policy.mjs");
    writeFileSync(policy, "export default {};\n");
    const resolved = resolvedConfig(home, [policy]);

    for (let seed = 0; seed < 1_024; seed++) {
      const definition = malformedDefinition(seed);
      await expect(loadPolicySet(resolved, { importCodePolicy: () => ({ default: definition }) }), `seed ${seed}`)
        .rejects.toBeInstanceOf(PolicyStartupError);
    }
  });

  test("fails unavailable sources and non-global code references without fallback", async () => {
    const home = fixtureDirectory();
    const missing = join(home, "missing.policy.mjs");
    await expect(loadPolicySet(resolvedConfig(home, [missing]), { importCodePolicy: () => ({ default: frozenDefinition() }) }))
      .rejects.toThrow(missing);

    await expect(loadPolicySet({
      global: loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }),
      sources: [{ path: missing, scope: "project" }],
    }, { importCodePolicy: () => ({ default: frozenDefinition() }) })).rejects.toThrow("only in global configuration");
  });

  test("property: 1,024 duplicate reference permutations retain first canonical-source order", async () => {
    const home = fixtureDirectory();
    const directory = join(home, "policies");
    mkdirSync(directory);
    const first = join(directory, "first.policy.mjs");
    const second = join(directory, "second.policy.mjs");
    const alias = join(directory, "alias.policy.mjs");
    writeFileSync(first, "export default {};\n");
    writeFileSync(second, "export default {};\n");
    symlinkSync(first, alias);
    const expected = [realpathSync(first), realpathSync(second)];

    for (let seed = 0; seed < 1_024; seed++) {
      const references = seed % 2 === 0 ? [first, alias, second, first] : [alias, first, second, alias];
      const loaded = await loadPolicySet(resolvedConfig(home, references), {
        importCodePolicy: () => ({ default: frozenDefinition() }),
      });
      expect(loaded.sources.map((source) => source.canonicalPath), `seed ${seed}`).toEqual(expected);
    }
  });
});

function malformedDefinition(seed: number): object {
  if (seed % 4 === 0) {
    const definition = { ...frozenDefinition() };
    Object.defineProperty(definition, "hidden", { value: true });
    return Object.freeze(definition);
  }
  if (seed % 4 === 1) {
    const definition = { ...frozenDefinition(), [Symbol("hidden")]: true };
    return Object.freeze(definition);
  }
  if (seed % 4 === 2) {
    const definition = Object.create({ hidden: true }) as Record<string, unknown>;
    Object.assign(definition, frozenDefinition());
    return Object.freeze(definition);
  }
  const definition = Object.create({ apiVersion: 1 }) as Record<string, unknown>;
  Object.assign(definition, { layer: "permission", select: [], evaluate: () => ({ kind: "ignore" }) });
  return Object.freeze(definition);
}
