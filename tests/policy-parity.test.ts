import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import githubHttp from "../policies/code/github-http.policy.ts";
import genericReadOnly from "../policies/code/generic-read-only.policy.ts";
import kubectl from "../policies/code/kubectl.policy.ts";
import secretRead from "../policies/code/secret-read.policy.ts";
import unsupportedShellSource from "../policies/code/unsupported-shell-source.policy.ts";
import { analyzeBashWithPolicies, initBashParser, type LoadedBashPolicy, type ValidatedBashPolicy } from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-parity-"));
const policies = Object.freeze([
  loaded("/trusted/secret-read.policy.mjs", secretRead),
  loaded("/trusted/github-http.policy.mjs", githubHttp),
  loaded("/trusted/kubectl.policy.mjs", kubectl),
  loaded("/trusted/unsupported-shell-source.policy.mjs", unsupportedShellSource),
  loaded("/trusted/generic-read-only.policy.mjs", genericReadOnly),
]);

const guardPairs = Object.freeze([
  ["secret-read", secretRead, dsl("secret-read")],
  ["github-http", githubHttp, dsl("github-http")],
  ["kubectl", kubectl, dsl("kubectl")],
  ["unsupported-shell-source", unsupportedShellSource, dsl("unsupported-shell-source")],
] as const);

const dslPolicies = Object.freeze(guardPairs.map(([, , policy]) => policy as ValidatedBashPolicy));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("baseline guard code-policy parity", () => {
  test("differential: every current guard corpus outcome matches its DSL source", () => {
    for (const source of guardCorpus()) {
      expectPolicyParity(source);
    }
  });

  test("differential: exact-basename DSL selectors only select matching kubectl invocations", () => {
    const dsl = analyzeBashWithPolicies({ source: "echo https://api.github.com/user; cat README.md", policies: dslPolicies });

    expect(dsl.traces.filter((trace) => trace.source.canonicalPath.includes("kubectl"))).toHaveLength(0);
  });

  test("property: generated argument, wrapper, and source-order cases stay differential", () => {
    const violations = [
      "cat credentials.json",
      "curl https://api.github.com/user",
      "kubectl view-secret application",
    ];
    const safe = ["cat README.md", "curl https://example.test", "kubectl get pods"];
    const wrappers = [
      (command: string) => command,
      (command: string) => `env -i ${command}`,
      (command: string) => `strace -f ${command}`,
      (command: string) => `sh -c '${command}'`,
    ];
    for (let seed = 0; seed < 192; seed++) {
      const violation = violations[seed % violations.length]!;
      const prefix = safe[(seed * 7) % safe.length]!;
      const suffix = violations[(seed * 11) % violations.length]!;
      const source = `${prefix}; ${wrappers[seed % wrappers.length]!(violation)}; ${suffix}`;
      expectPolicyParity(source, `${seed}: ${source}`);
    }
  });

  test("matches baseline denials through wrappers, nested source, and execution gaps", () => {
    for (const source of [
      "cat credentials.json",
      "strace -f curl https://api.github.com/repos/acme/widgets/issues",
      "sh -c 'kubectl view-secret application'",
      "fish -c true",
      'fish -c "$(echo source)"',
      "< credentials.json",
      "(cat) < credentials.json",
      "{ cat; } < credentials.json",
    ]) {
      const legacy = analyzeBashWithPolicies({ source, policies });
      const generic = analyzeBashWithPolicies({ source, policies });

      expect(legacy.decision, source).toBe("deny");
      expect(generic.decision, source).toBe("deny");
      const trace = generic.traces.find((candidate) => candidate.decision.kind === "deny");
      expect(trace, source).toBeDefined();
      expect(trace?.decision, source).toMatchObject({
        kind: "deny",
        reason: legacy.traces.find((candidate) => candidate.decision.kind === "deny")?.decision.kind === "deny"
          ? legacy.traces.find((candidate) => candidate.decision.kind === "deny")?.decision.reason : [],
      });
      expect(trace?.decision, source).toMatchObject({
        audit: trace?.event.kind === "invocation" ? { invocation: trace.event } : { gap: trace?.event },
      });
    }
  });

  test("safe guard paths never authorize and a later denial dominates indeterminate work", () => {
    for (const source of [
      "cat README.md",
      "curl https://example.test",
      "kubectl get pods",
      "unknown-command; kubectl get secret app; cat credentials.json",
    ]) {
      const generic = analyzeBashWithPolicies({ source, policies });
      expect(generic.decision, source).toBe(source.endsWith("credentials.json") ? "deny" : "defer");
      expect(generic.traces.every((trace) => trace.decision.kind !== "allow"), source).toBeTrue();
    }
  });

  test("retains generic policy denials for binding-derived source and kubectl audit values", () => {
    const bindingSource = analyzeBashWithPolicies({ source: "SCRIPT='cat credentials.json'; sh -c \"$SCRIPT\"", policies });
    const kubectlSource = analyzeBashWithPolicies({ source: "kubectl get secret application", policies });

    expect(bindingSource.decision).toBe("deny");
    expect(bindingSource.traces.find((trace) => trace.decision.kind === "deny")?.event.provenance.route)
      .toContain("binding-derived-script");
    const kubectlDecision = kubectlSource.traces.find((trace) => trace.decision.kind === "defer")?.decision;
    expect(kubectlDecision).toMatchObject({ kind: "defer" });
    if (kubectlDecision?.kind === "defer") {
      expect((kubectlDecision.audit?.invocation as { readonly argv: readonly { readonly value: string }[] }).argv)
        .toEqual([{ kind: "known", value: "get" }, { kind: "known", value: "secret" }, { kind: "known", value: "application" }]);
    }
  });

  test("projects early structural boundaries into generic policy events", () => {
    const fish = analyzeBashWithPolicies({ source: 'fish -c "$(echo source)"', policies });
    const redirect = analyzeBashWithPolicies({ source: "{ cat; } < credentials.json", policies });

    expect(fish.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "unsupported-shell-source" }));
    expect(redirect.events).toContainEqual(expect.objectContaining({
      kind: "invocation",
      executable: null,
      redirects: [{ kind: "input", target: { kind: "known", value: "credentials.json" } }],
    }));
  });

  test("property: wrapper and source order preserve every baseline denial", () => {
    const blocked = ["cat credentials.json", "curl https://api.github.com/user", "kubectl view-secret app"];
    const wrappers = [(source: string) => source, (source: string) => `env -i ${source}`, (source: string) => `sh -c '${source}'`];

    for (let seed = 0; seed < 96; seed++) {
      const source = wrappers[seed % wrappers.length]!(blocked[seed % blocked.length]!);
      expect(analyzeBashWithPolicies({ source: `unknown-command; ${source}`, policies }).decision, `${seed}: ${source}`).toBe("deny");
    }
  });

  test("allows generic compound reads without foreign policy deferrals", () => {
    const result = analyzeBashWithPolicies({
      source: "git diff HEAD; sha256sum README.md",
      policies,
      initialEnvironment: { kind: "verified", values: {} },
    });

    expect(result.decision).toBe("allow");
  });
});

function dsl(name: string): ValidatedBashPolicy {
  const path = new URL(`../policies/dsl/${name}.policy.json`, import.meta.url);
  return createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(path, "utf8"))), path.pathname) as ValidatedBashPolicy;
}

function expectPolicyParity(source: string, label = source): void {
  const events = analyzeBashWithPolicies({ source, policies: dslPolicies }).events;
  for (const event of events) {
    for (const [name, code, policy] of guardPairs) {
      expect(code.evaluate(event), `${label}: ${name}`).toEqual(policy.evaluate(event));
    }
  }
}

function guardCorpus(): readonly string[] {
  return [
    "cat credentials.json", "cat README.md", "cat .env", "cat .env.example",
    "wc < credentials.json", "< credentials.json", "{ cat; } < credentials.json",
    "curl https://api.github.com/repos/acme/widgets/issues", "curl https://API.GITHUB.COM./user", "curl https://example.test",
    "wget https://raw.githubusercontent.com/acme/widgets/main/README.md", "echo https://api.github.com/user",
    "kubectl view-secret application", "kubectl get secret application", "kubectl get secrets", "kubectl get pods",
    "kubectl --namespace default get secret application", "kubectl get pod secrets/application",
    "fish -c true", "fish --command=\"$(echo source)\"", "fish --version",
    "strace -f curl https://api.github.com/user", "sh -c 'kubectl view-secret application'",
    "unknown-command; cat credentials.json", "curl https://example.test; kubectl view-secret application",
  ];
}

function loaded(path: string, definition: Omit<LoadedBashPolicy, "source"> & { readonly apiVersion: 1 }): ValidatedBashPolicy {
  return Object.freeze({
    source: Object.freeze({ canonicalPath: path }),
    layer: definition.layer,
    select: definition.select,
    evaluate: definition.evaluate,
  }) as ValidatedBashPolicy;
}
