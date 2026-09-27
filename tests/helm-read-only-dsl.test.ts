import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const path = new URL("../policies/dsl/helm-read-only.policy.json", import.meta.url);
const policy = createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(path, "utf8"))), path.pathname);

function decision(args: readonly string[], overrides: Record<string, unknown> = {}): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "helm" },
    executableIdentity: { qualification: "incomplete", spelling: "helm", basename: "helm", chain: [], failure: { kind: "not-found" } },
    argv: args.map((value) => ({ kind: "known" as const, value })),
    environment: {}, missingBindings: "unset", redirects: [], assignments: {},
    span: { start: 0, end: 0 }, provenance: { route: ["direct"] }, inPipeline: false, processEffect: "none",
    ...overrides,
  } as any).kind;
}

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length < 2) return [[...values]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((tail) => [value, ...tail]));
}

describe("helm read-only DSL policy", () => {
  test("permits the reviewed Helm 4.3.0 command paths and aliases", () => {
    for (const args of [
      ["--help"], ["help", "upgrade"], ["env"], ["version", "--short"], ["completion", "zsh"],
      ["repo", "list"], ["repo", "ls", "--output=table"], ["list", "--output", "table"],
      ["ls", "--namespace=platform", "--deployed"], ["hist", "release", "--show-rollback-revision"],
      ["show", "chart", "oci://registry.example/chart", "--version", "1.2.3"],
      ["inspect", "chart", "example/chart"], ["search", "hub", "nginx", "--output=table"],
      ["search", "repo", "nginx", "--devel"], ["verify", "chart.tgz"],
      ["lint", "chart", "--values", "values.yaml", "--set", "replicas=2"],
      ["template", "release", "chart", "--dry-run=server", "--values", "values.yaml", "--set-string", "mode=prod"],
    ]) expect(decision(args), args.join(" ")).toBe("allow");
  });

  test("property: list flags and namespace placement are ordering-insensitive", () => {
    const blocks = [["--namespace", "platform"], ["--all-namespaces"], ["--output=table"]];
    for (const order of permutations(blocks)) expect(decision(["list", ...order.flat()]), order.flat().join(" ")).toBe("allow");
    expect(decision(["--namespace", "platform", "list", "--all-namespaces", "--output=table"])).toBe("allow");
    for (const command of [["env"], ["version"], ["completion", "zsh"], ["repo", "list"], ["show", "chart", "c"], ["verify", "c"], ["lint", "c"], ["template", "c"]]) {
      expect(decision(["--namespace", "platform", ...command]), command.join(" ")).toBe("defer");
    }
  });

  test("generated: every reviewed short alias and output form remains command-scoped", () => {
    const outputForms = [["--output", "table"], ["--output=table"], ["-o", "table"], ["-otable"]];
    const outputCommands = [["repo", "list"], ["list"], ["history", "release"], ["search", "hub", "nginx"], ["search", "repo", "nginx"]];
    for (const command of outputCommands) for (const form of outputForms) {
      expect(decision([...command, ...form]), `${command.join(" ")} ${form.join(" ")}`).toBe("allow");
    }
    for (const args of [
      ["list", "-A"], ["list", "-Aotable"], ["list", "-nplatform"], ["history", "release", "-n", "platform"],
      ["search", "repo", "nginx", "-l"], ["lint", "chart", "-fvalues.yaml"],
      ["template", "chart", "-aapps/v1"], ["template", "chart", "-sonly.yaml"],
    ]) expect(decision(args), args.join(" ")).toBe("allow");
  });

  test("permits the reviewed Helm subset regardless of core-projected provenance", () => {
    for (const route of [["direct", "transparent-wrapper"], ["direct", "shell-command"], ["direct", "eval"]]) {
      expect(decision(["list"], { provenance: { route } }), route.join("/")).toBe("allow");
    }
  });

  test("delegates values of permitted options to Helm", () => {
    for (const args of [["template", "chart", "--set-file", "--keyring"], ["template", "chart", "--values", "--output-dir"], ["list", "--namespace", "--deployed"], ["list", "--namespace", "--"], ["template", "chart", "--values", "--"], ["template", "chart", "--set", "--"], ["show", "chart", "c", "--repo", "--"]]) {
      expect(decision(args), args.join(" ")).toBe("allow");
    }
  });

  test("permits unresolved values only where the reviewed grammar treats them as opaque", () => {
    const unknown = { kind: "unknown", reason: { kind: "expansion" } };
    expect(decision([], { argv: [{ kind: "known", value: "list" }, { kind: "known", value: "--namespace" }, unknown] })).toBe("allow");
    expect(decision([], { argv: [{ kind: "known", value: "history" }, unknown] })).toBe("defer");
  });

  test("defers release-content, write-capable, malformed, and unsafe routes", () => {
    for (const args of [
      [], ["status", "release"], ["get", "values", "release"], ["get", "manifest", "release"],
      ["list", "--output=json"], ["history", "release", "--output", "yaml"],
      ["repo", "update"], ["install", "release", "chart"], ["template", "release", "chart", "--dependency-update"],
      ["template", "release", "chart", "--output-dir", "rendered"], ["template", "release", "chart", "--post-renderer", "rewrite"],
      ["template", "release", "chart", "--dry-run=none"], ["template", "release", "chart", "--dry-run", "client"], ["history", "release", "extra"],
      ["history", "release", "--dry-run=server"], ["verify", "chart.tgz", "--set", "x=y"],
      ["template", "release", "chart", "--max=5"], ["list", "--selector"], ["verify", "chart.tgz", "--keyring", "pubring.gpg"],
      ["list", "--unknown"], ["list", "--"],
    ]) expect(decision(args), args.join(" ")).toBe("defer");

    expect(decision(["list"], { redirects: [{ kind: "output", target: { kind: "known", value: "out" } }] })).toBe("defer");
    expect(decision(["list"], { assignments: { HELM_KUBETOKEN: { kind: "known", value: "token" } } })).toBe("defer");
    expect(decision(["list"], { executable: { kind: "known", value: "/usr/bin/helm" } })).toBe("defer");
    expect(decision(["list"], { environment: { KUBECONFIG: { kind: "known", value: "cluster" } } })).toBe("defer");
  });
});
