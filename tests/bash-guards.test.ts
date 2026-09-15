import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  STRICT_BASH_PROFILE_EXECUTABLES,
  evaluateBashGuards,
  evaluateConfiguredBash,
  initBashParser,
  type BashProfileSnapshot,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-guards-"));
const profileSnapshot: BashProfileSnapshot = Object.freeze({
  readOnlyBash: false,
  ghApiReadOnly: false,
  ghReadOnly: false,
  helmReadOnly: false,
  strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
  ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
  limits: Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 }),
});

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("single-pass Bash guards", () => {
  test("returns a structured block for each baseline policy", () => {
    for (const [source, name] of [
      ["cat credentials.json", "secret-read"],
      ["curl https://api.github.com/repos/acme/widgets/issues", "github-http"],
      ["kubectl view-secret application", "kubectl"],
    ] as const) {
      expect(evaluateBashGuards({ source })).toMatchObject({
        kind: "block",
        policy: { name, decision: "deny" },
      });
    }
  });

  test("passes without granting permission on safe, unknown, malformed, and failed analysis", () => {
    expect(evaluateBashGuards({ source: "cat README.md" })).toMatchObject({ kind: "pass", status: "complete" });
    expect(evaluateBashGuards({ source: "unknown-command" })).toMatchObject({ kind: "pass", status: "indeterminate" });
    expect(evaluateBashGuards({ source: "if then" })).toMatchObject({ kind: "pass", status: "indeterminate" });
    expect(evaluateBashGuards({
      source: "cat README.md",
      limits: { maxFunctionDepth: 0, maxNestedScriptDepth: 0, maxSteps: 0, maxWorkItems: 0 },
    })).toMatchObject({ kind: "pass", status: "failure" });
  });

  test("retains kubectl Secret review evidence without hard-blocking", () => {
    const result = evaluateBashGuards({ source: "kubectl get Secret application" });

    expect(result).toMatchObject({ kind: "pass", status: "indeterminate" });
    expect(result.policies).toContainEqual(expect.objectContaining({
      name: "kubectl",
      decision: "defer",
      kubectl: expect.objectContaining({ secretReview: true }),
    }));
  });

  test("reports the first reachable denial when different guards match", () => {
    expect(evaluateBashGuards({
      source: "cat credentials.json; curl https://api.github.com/user; kubectl view-secret application",
    })).toMatchObject({ kind: "block", policy: { name: "secret-read" } });
    expect(evaluateBashGuards({
      source: "curl https://api.github.com/user; cat credentials.json; kubectl view-secret application",
    })).toMatchObject({ kind: "block", policy: { name: "github-http" } });
    expect(evaluateBashGuards({
      source: "kubectl view-secret application; cat credentials.json; curl https://api.github.com/user",
    })).toMatchObject({ kind: "block", policy: { name: "kubectl" } });
  });

  test("does not expose binding-derived values in any guard evidence", () => {
    const marker = "opaque-guard-canary";
    for (const [source, values] of [
      ["curl \"$URL\"", { URL: `https://api.github.com/user?value=${marker}` }],
      ["cat \"$FILE\"", { FILE: `${marker}.credentials.json` }],
      ["wc < \"$FILE\"", { FILE: `${marker}.credentials.json` }],
      ["kubectl \"$ACTION\"", { ACTION: marker }],
      ["kubectl get \"$RESOURCE\"", { RESOURCE: marker }],
      ["sh -c 'cat \"$FILE\"'", { FILE: `${marker}.credentials.json` }],
    ] as const) {
      const result = evaluateBashGuards({
        source,
        initialEnvironment: { kind: "verified", values },
      });
      if ("FILE" in values) {
        expect(result).toMatchObject({ kind: "block", policy: { name: "secret-read" } });
      }
      expect(JSON.stringify(result), source).not.toContain(marker);
    }
  });

  test("redacts binding-derived ghPrCreate repositories", () => {
    const marker = "opaque-gh-pr-repository";
    const result = evaluateBashGuards({
      source: "gh pr create --repo \"$REPOSITORY\" --fill",
      initialEnvironment: { kind: "verified", values: { REPOSITORY: `github.com/${marker}/repository` } },
      ghPrCreatePolicy: { enabled: true, allowedRepositories: ["acme/widgets"], allowedOrganizations: [] },
    });

    expect(result).toMatchObject({ kind: "block", policy: { name: "gh-pr-create" } });
    expect(JSON.stringify(result)).not.toContain(marker);
  });

  test("redacts known kubectl actions resolved from bindings", () => {
    for (const [source, values, resolvedPhrase] of [
      ["kubectl \"$ACTION\"", { ACTION: "version" }, "version"],
      ["strace kubectl rollout \"$ACTION\" deployment/app", { ACTION: "status" }, "rollout status"],
      ["sh -c 'kubectl auth \"$ACTION\"'", { ACTION: "whoami" }, "auth whoami"],
    ] as const) {
      const result = evaluateBashGuards({ source, initialEnvironment: { kind: "verified", values } });
      const policy = result.policies.find((candidate) => candidate.name === "kubectl");
      expect(policy?.reason ?? "", source).not.toContain(resolvedPhrase);
    }
  });

  test("preserves literal kubectl audit fields when only a flag value comes from a binding", () => {
    const source = "NS=default; kubectl --namespace \"$NS\" get secret application";

    expect(evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot }).audit.events)
      .toEqual([{ kind: "kubectl-secret", policy: "kubectl", fields: {
        kubectl_subcommand: "get", resource: "secret", command_length: source.length,
      } }]);
    expect(evaluateConfiguredBash({
      source: "RESOURCE=secret; kubectl get \"$RESOURCE\"",
      initialEnvironment: { kind: "unavailable" },
      profileSnapshot,
    }).audit.events[0]?.fields).toMatchObject({ kubectl_subcommand: "get", resource: null });
  });

  test("property: supported wrappers preserve every baseline denial", () => {
    const violations = [
      ["cat credentials.json", "secret-read"],
      ["curl https://api.github.com/user", "github-http"],
      ["kubectl view-secret application", "kubectl"],
    ] as const;
    const wrappers = [
      (command: string) => command,
      (command: string) => `env -i ${command}`,
      (command: string) => `strace -f ${command}`,
      (command: string) => `timeout 5s ${command}`,
      (command: string) => `sh -c '${command}'`,
    ];

    for (const [command, name] of violations) {
      for (const wrap of wrappers) {
        expect(evaluateBashGuards({ source: `unknown-command; ${wrap(command)}` }), wrap(command))
          .toMatchObject({ kind: "block", policy: { name } });
      }
    }
  });

  test("property: source order deterministically selects among proven denials", () => {
    const violations = [
      ["cat credentials.json", "secret-read"],
      ["curl https://api.github.com/user", "github-http"],
      ["kubectl view-secret application", "kubectl"],
    ] as const;

    for (let first = 0; first < violations.length; first++) {
      for (let second = 0; second < violations.length; second++) {
        if (first === second) continue;
        const [firstCommand, firstPolicy] = violations[first]!;
        const [secondCommand] = violations[second]!;
        expect(evaluateBashGuards({ source: `${firstCommand}; ${secondCommand}` }))
          .toMatchObject({ kind: "block", policy: { name: firstPolicy } });
      }
    }
  });
});
