import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { analyzeBashWithPolicies } from "../src/authorization.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";
import { initBashParser } from "../src/shell.ts";

const discoveryPath = new URL("../policies/dsl/command-discovery.policy.json", import.meta.url);
const discovery = createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(discoveryPath, "utf8"))), discoveryPath.pathname);
const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-command-discovery-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "packages", "core", "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

function commandDecision(argv: readonly ({ readonly kind: "known"; readonly value: string } | { readonly kind: "unknown"; readonly reason: { readonly kind: string } })[], overrides: Record<string, unknown> = {}): string {
  return discovery.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "command" },
    executableIdentity: { qualification: "incomplete", spelling: "command", basename: "command", chain: [], failure: { kind: "not-found" } },
    argv,
    environment: {}, missingBindings: "unset", redirects: [], assignments: {},
    span: { start: 0, end: 0 }, provenance: { route: ["direct"] }, inPipeline: false, processEffect: "none",
    ...overrides,
  } as any).kind;
}

function exactPermission(name: string, executable: string, argv: readonly string[]) {
  return createDslPolicy(compilePolicyDocument(parsePolicyDocument(JSON.stringify({
    language: "safety-core/bash-policy-v1",
    layer: "permission",
    select: [{ executable: { projection: "basename", equals: executable } }],
    registers: {}, folds: {}, options: {}, fragments: {}, start: "start",
    states: {
      start: {
        cases: argv.map((word, index) => ({
          when: { call: "equals", args: [{ ref: "word" }, word] },
          action: { consume: "word", next: index + 1 === argv.length ? "end" : `word${index + 1}` },
        })),
        default: { decision: "defer" }, end: { decision: "defer" },
      },
      ...Object.fromEntries(argv.slice(1).map((word, index) => [`word${index + 1}`, {
        cases: [{ when: { call: "equals", args: [{ ref: "word" }, word] }, action: { consume: "word", next: index + 2 === argv.length ? "end" : `word${index + 2}` } }],
        default: { decision: "defer" }, end: { decision: "defer" },
      }])),
      end: { cases: [], default: { decision: "defer" }, end: { decision: "allow", reason: [name] } },
    },
  }))), `/${name}.policy.json`);
}

describe("command discovery DSL policy", () => {
  test("permits exactly one direct -v command lookup", () => {
    for (const name of ["helm", "git", "tools/helm"]) {
      expect(commandDecision([{ kind: "known", value: "-v" }, { kind: "known", value: name }]), name).toBe("allow");
    }
  });

  test("property: every documented equivalent command name remains permitted", () => {
    for (let index = 0; index < 128; index++) {
      const name = index % 2 === 0 ? `tool${index}` : `bin/tool${index}`;
      expect(commandDecision([{ kind: "known", value: "-v" }, { kind: "known", value: name }]), name).toBe("allow");
    }
  });

  test("defers flags, malformed names, envelope effects, and unresolved names", () => {
    const known = (value: string) => ({ kind: "known" as const, value });
    for (const argv of [["-V", "helm"], ["-p", "-v", "helm"], ["-v"], ["-v", "helm", "git"], ["-v", "--"], ["-v", ""], ["helm", "list"]]) {
      expect(commandDecision(argv.map(known)), argv.join(" ")).toBe("defer");
    }
    expect(commandDecision([known("-v"), { kind: "unknown", reason: { kind: "expansion" } }])).toBe("defer");
    expect(commandDecision([known("-v"), known("helm")], { assignments: { PATH: { kind: "known", value: "/tmp" } } })).toBe("defer");
    expect(commandDecision([known("-v"), known("helm")], { redirects: [{ kind: "output", target: known("out") }] })).toBe("defer");
    expect(commandDecision([known("-v"), known("helm")], { executable: { kind: "known", value: "/bin/command" } })).toBe("defer");
  });

  test("requires independent outer and nested permissions for command execution", () => {
    const outer = exactPermission("outer-command", "command", ["helm", "list"]);
    const nested = exactPermission("nested-helm", "helm", ["list"]);
    const options = { source: "command helm list", initialEnvironment: { kind: "verified" as const, values: {} } };

    const fullyCovered = analyzeBashWithPolicies({ ...options, policies: [discovery, outer, nested] });
    expect(fullyCovered.decision).toBe("allow");
    expect(fullyCovered.events.map((event) => event.kind === "invocation" && event.executable?.kind === "known" ? event.executable.value : event.kind)).toEqual(["command", "helm"]);

    expect(analyzeBashWithPolicies({ ...options, policies: [discovery, nested] }).decision).toBe("defer");
    expect(analyzeBashWithPolicies({ ...options, policies: [discovery, outer] }).decision).toBe("defer");
  });
});
