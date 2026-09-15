import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  STRICT_BASH_PROFILE_EXECUTABLES,
  evaluateConfiguredBash,
  initBashParser,
  type BashProfileSnapshot,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-configured-"));
const limits = Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 });

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

function snapshot(overrides: Partial<BashProfileSnapshot> = {}): BashProfileSnapshot {
  return Object.freeze({
    readOnlyBash: false,
    ghApiReadOnly: false,
    ghReadOnly: false,
    helmReadOnly: false,
    strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
    ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
    limits,
    ...overrides,
  });
}

function evaluate(source: string, profileSnapshot: BashProfileSnapshot) {
  return evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot });
}

describe("configured Bash permissions", () => {
  test("auto-allows only one profile's complete coverage", () => {
    const profiles = snapshot({
      ghReadOnly: true,
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    });

    expect(evaluate("gh label list", profiles).permission).toMatchObject({ kind: "allow", profile: "ghReadOnly" });
    expect(evaluate("gh label list; gh repo list", profiles).permission).toMatchObject({ kind: "allow", profile: "ghReadOnly" });
    expect(evaluate("gh label list; docker image ls", profiles).permission).toEqual({ kind: "defer" });
    expect(evaluate("docker image ls; gh label list", profiles).permission).toEqual({ kind: "defer" });
    expect(evaluate("gh label list; unknown-command", profiles).permission).toEqual({ kind: "defer" });
    expect(evaluate("gh api user; cat README.md", snapshot({ ghApiReadOnly: true })).permission).toEqual({ kind: "defer" });

    const jfrog = snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, jfrogReadOnly: true }),
    });
    expect(evaluate("jf rt search artifact", jfrog).permission).toMatchObject({ kind: "allow", profile: "jfrogReadOnly" });
    expect(evaluate("jfrog rt search artifact", jfrog).permission).toMatchObject({ kind: "allow", profile: "jfrogReadOnly" });
  });

  test("keeps gh ownership deterministic while ghPrCreate is active", () => {
    const profiles = snapshot({
      ghReadOnly: true,
      ghApiReadOnly: true,
      ghPrCreate: Object.freeze({
        enabled: true,
        allowedRepositories: Object.freeze(["acme/widgets"]),
        allowedOrganizations: Object.freeze([]),
      }),
    });

    expect(evaluate("gh pr create --repo github.com/acme/widgets --fill", profiles).permission)
      .toMatchObject({ kind: "allow", profile: "ghPrCreate" });
    expect(evaluate("gh api user", profiles).permission).toMatchObject({ kind: "deny", profile: "ghPrCreate" });
    expect(evaluate("gh api user", profiles).guards).toMatchObject({ kind: "block", policy: { name: "gh-pr-create" } });
    expect(evaluate("gh label list", profiles).permission).toMatchObject({ kind: "allow", profile: "ghReadOnly" });
  });

  test("keeps guard, permission, failure, and audit views separate and redacted", () => {
    const noProfiles = evaluate("cat README.md", snapshot());
    expect(noProfiles.guards).toMatchObject({ kind: "pass" });
    expect(noProfiles.permission).toEqual({ kind: "ignore" });

    const kubectl = evaluate("kubectl get Secret application", snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, kubectlReadOnly: true }),
    }));
    expect(kubectl.permission).toEqual({ kind: "defer" });
    expect(kubectl.audit.events).toEqual([{
      kind: "kubectl-secret",
      policy: "kubectl",
      fields: { kubectl_subcommand: "get", resource: "secret", command_length: "kubectl get Secret application".length },
    }]);
    expect(evaluate("kubectl get pods", snapshot()).audit.events).toEqual([]);
    expect(evaluate("RESOURCE=secret; kubectl get \"$RESOURCE\"", snapshot()).audit.events[0]?.fields).toEqual({
      kubectl_subcommand: "get", resource: null, command_length: "RESOURCE=secret; kubectl get \"$RESOURCE\"".length,
    });
    expect(evaluate("kubectl get secrets.v1 application", snapshot()).audit.events[0]?.fields).toEqual({
      kubectl_subcommand: "get", resource: "secrets", command_length: "kubectl get secrets.v1 application".length,
    });

    const serialized = JSON.stringify(evaluate("CANARY_VALUE=never-emit; gh label list", snapshot({ ghReadOnly: true })));
    expect(serialized).not.toContain("CANARY_VALUE");
    expect(serialized).not.toContain("never-emit");
    expect(Object.isFrozen(kubectl)).toBe(true);
    expect(Object.isFrozen(kubectl.audit.events)).toBe(true);
    expect(Object.isFrozen(kubectl.audit.events[0]!)).toBe(true);
  });

  test("preserves wrapper coverage and native deferral for incomplete analysis", () => {
    const gh = snapshot({ ghReadOnly: true });
    expect(evaluate("TOOL=gh; strace $TOOL label list", gh).permission)
      .toMatchObject({ kind: "allow", profile: "ghReadOnly" });
    expect(evaluate("strace -o trace.log gh label list", gh).permission).toEqual({ kind: "defer" });
    expect(evaluate("if then", gh).permission.kind).not.toBe("allow");

    const exhausted = evaluate("gh label list", snapshot({
      ghReadOnly: true,
      limits: Object.freeze({ ...limits, maxSteps: 0 }),
    }));
    expect(exhausted.analysis.status).toBe("failure");
    expect(exhausted.analysis.failure).toEqual({ budget: "max-steps" });
    expect(exhausted.permission.kind).not.toBe("allow");
  });

  test("property: source and profile order cannot turn mixed ownership into an allow", () => {
    const profiles = snapshot({
      ghReadOnly: true,
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    });
    const gh = ["gh label list", "gh repo list", "gh auth status"];
    const docker = ["docker image ls", "docker volume ls", "docker network list"];
    for (const left of gh) {
      for (const right of docker) {
        expect(evaluate(`${left}; ${right}`, profiles).permission, `${left}; ${right}`).toEqual({ kind: "defer" });
        expect(evaluate(`${right}; ${left}`, profiles).permission, `${right}; ${left}`).toEqual({ kind: "defer" });
      }
    }
  });
});
