import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { analyzeBashWithPolicies, completePolicyInitialEnvironment, initBashParser, type BashPolicyEvent, type ValidatedBashPolicy } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-events-"));
const allow = Object.freeze({ kind: "allow" as const, reason: Object.freeze([{ kind: "literal" as const, value: "covered" }]) });
const deny = Object.freeze({ kind: "deny" as const, reason: Object.freeze([{ kind: "literal" as const, value: "denied" }]) });

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "packages", "core", "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("Bash generic policy events", () => {
  test("retains exact modeled invocation data without redaction", () => {
    const result = analyzeBashWithPolicies({
      source: 'CANARY=exact-value gh "$UNKNOWN" > response.json',
      initialEnvironment: { kind: "unavailable" },
      policies: [policy("permission", () => allow)],
    });
    const event = onlyInvocation(result.events);

    expect(event.environment.CANARY).toEqual({ kind: "known", value: "exact-value" });
    expect(event.argv[0]).toEqual({ kind: "unknown", reason: expect.any(Object) });
    expect(event.redirects).toEqual([{ kind: "output", target: { kind: "known", value: "response.json" } }]);
    expect(event.assignments.CANARY).toEqual({ kind: "known", value: "exact-value" });
    expect(event.provenance).toEqual({ route: ["direct"] });
    expect(event.inPipeline).toBeFalse();
    expect(event.processEffect).toBe("none");
    expect(event.span).toEqual({ start: 0, end: 'CANARY=exact-value gh "$UNKNOWN" > response.json'.length });
    expect(Object.isFrozen(event)).toBeTrue();
    expect(Object.isFrozen(event.environment)).toBeTrue();
    expect(Object.isFrozen(event.assignments)).toBeTrue();
    expect(Object.isFrozen(event.assignments.CANARY)).toBeTrue();
    expect(() => { (event.assignments as Record<string, unknown>).CANARY = "mutated"; }).toThrow();
    expect(result.decision).toBe("defer");
  });

  test("retains core denials that occur before dispatch as an invocation event and request deny", () => {
    const result = analyzeBashWithPolicies({
      source: "gh < credentials.json",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(result.events)).toMatchObject({
      executable: { kind: "known", value: "gh" },
      redirects: [{ kind: "input", target: { kind: "known", value: "credentials.json" } }],
    });
    expect(result.decision).toBe("deny");
  });

  test("reports runner and walker budget cutoffs as execution gaps", () => {
    const runnerExhausted = analyzeBashWithPolicies({
      source: "gh one",
      initialEnvironment: { kind: "verified", values: {} },
      limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10 },
      policies: [policy("permission", () => allow)],
    });
    const walkerExhausted = analyzeBashWithPolicies({
      source: "gh one; gh two",
      initialEnvironment: { kind: "verified", values: {} },
      limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 10, maxWorkItems: 1 },
      policies: [policy("permission", () => allow)],
    });

    expect(runnerExhausted.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "max-steps" }));
    expect(walkerExhausted.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "max-work-items" }));
    expect(runnerExhausted.decision).toBe("defer");
    expect(walkerExhausted.decision).toBe("defer");
  });

  test("retains absent-binding availability independently from materialized bindings", () => {
    const unavailable = analyzeBashWithPolicies({
      source: "gh status",
      initialEnvironment: { kind: "unavailable" },
      policies: [policy("permission", () => allow)],
    });
    const verified = analyzeBashWithPolicies({
      source: "gh status",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(unavailable.events).missingBindings).toBe("unknown");
    expect(onlyInvocation(verified.events).missingBindings).toBe("unset");
  });

  test("analyzes inherited function bodies while preserving the exact exported environment entry", () => {
    const body = "() { gh api user -X POST; }";
    const result = analyzeBashWithPolicies({
      source: "helm list",
      initialEnvironment: completePolicyInitialEnvironment({ "BASH_FUNC_helm%%": body }),
      policies: [policy("permission", () => allow), policy("guard", (event) =>
        event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "gh" ? deny : { kind: "ignore" })],
    });
    expect(result.decision).toBe("deny");
    expect(result.events).not.toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "invalid-imported-bash-function" }));
    expect(result.events.filter((event) => event.kind === "invocation").map((event) => event.executable?.kind === "known" ? event.executable.value : null)).toEqual(["gh"]);
    expect(onlyInvocation(result.events).environment["BASH_FUNC_helm%%"]).toEqual({ kind: "known", value: body });
    expect(onlyInvocation(result.events)).toMatchObject({ span: { start: 0, end: "helm list".length }, provenance: { route: ["direct", "imported-function"] } });
  });

  test("a malformed exported definition creates a request-wide uncertainty event, without hiding denials", () => {
    const initialEnvironment = completePolicyInitialEnvironment({ "BASH_FUNC_helm%%": "not a function" });
    const quiet = analyzeBashWithPolicies({ source: ":", initialEnvironment, policies: [policy("permission", () => allow)] });
    expect(quiet.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "invalid-imported-bash-function" }));
    expect(quiet.decision).toBe("defer");
    const denied = analyzeBashWithPolicies({
      source: "gh api user -X POST", initialEnvironment,
      policies: [policy("permission", () => allow), policy("guard", (event) =>
        event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "gh" ? deny : { kind: "ignore" })],
    });
    expect(denied.decision).toBe("deny");
  });

  test("resolves shell functions before builtins, but external wrappers and command bypass shell functions", () => {
    const initialEnvironment = completePolicyInitialEnvironment({
      "BASH_FUNC_helm%%": "() { gh from-function; }",
      "BASH_FUNC_command%%": "() { gh shadowed-command; }",
      "BASH_FUNC_printf%%": "() { gh shadowed-builtin; }",
    });
    const targets = (source: string) => analyzeBashWithPolicies({ source, initialEnvironment, policies: [policy("permission", () => allow)] })
      .events.filter((event) => event.kind === "invocation")
      .map((event) => [event.executable?.kind === "known" ? event.executable.value : null, event.executionTarget]);
    expect(targets("helm list")).toEqual([["gh", "external-path"]]);
    expect(targets("printf ok")).toEqual([["gh", "external-path"]]);
    expect(targets("command helm list")).toEqual([["gh", "external-path"]]);
    expect(targets("builtin command helm list")).toEqual([["builtin", "builtin"], ["command", "builtin"], ["helm", "external-path"]]);
    expect(targets("strace -f helm list")).toEqual([["strace", "external-path"], ["helm", "external-path"]]);
    expect(targets("env helm list")).toEqual([["env", "external-path"], ["helm", "external-path"]]);
    expect(targets("watch helm list")).toEqual([["watch", "external-path"], ["helm", "external-path"]]);
    expect(targets("builtin printf ok")).toEqual([["builtin", "builtin"]]);
  });

  test("local definitions replace imported functions, and unset -f removes them", () => {
    const initialEnvironment = completePolicyInitialEnvironment({ "BASH_FUNC_helm%%": "() { gh imported; }" });
    const run = (source: string) => analyzeBashWithPolicies({ source, initialEnvironment, policies: [policy("permission", () => allow)] });
    expect(run("helm(){ gh local; }; helm").events.filter((event) => event.kind === "invocation" && event.executable?.kind === "known").map((event) => event.argv[0]?.kind === "known" ? event.argv[0].value : "")).toEqual(["local"]);
    const unset = run("unset -f helm; helm list");
    expect(unset.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "helm" }, executionTarget: "external-path" }));
  });

  test("a new Bash process imports functions from its own exported environment", () => {
    const initialEnvironment = completePolicyInitialEnvironment({ "BASH_FUNC_helm%%": "() { gh imported; }" });
    const run = (source: string) => analyzeBashWithPolicies({ source, initialEnvironment, policies: [policy("permission", () => allow)] });
    const inherited = run("bash -c 'helm list'");
    expect(inherited.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "gh" } }));
    const cleared = run("env -i bash -c 'helm list'");
    expect(cleared.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "helm" }, executionTarget: "external-path" }));
    for (const source of ["env -u 'BASH_FUNC_helm%%' bash -c 'helm list'", "bash -p -c 'helm list'", "sh -c 'helm list'"]) {
      expect(run(source).events, source).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "helm" }, executionTarget: "external-path" }));
    }
    const redefined = run("helm(){ gh new-body; }; bash -c 'helm list'");
    expect(redefined.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "gh" }, argv: [{ kind: "known", value: "new-body" }] }));
    expect(redefined.events).not.toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "gh" }, argv: [{ kind: "known", value: "imported" }] }));
    const unexported = run("export -nf helm; bash -c 'helm list'");
    expect(unexported.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "helm" }, executionTarget: "external-path" }));
    for (const flags of ["-nf", "-fn", "-n -f", "-f -n"]) {
      const result = run(`export ${flags} helm; bash -c 'helm list'`);
      expect(result.events, flags).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "helm" }, executionTarget: "external-path" }));
    }
    const uncertain = run('read NAME; unset -f "$NAME"; bash -c "helm list"');
    expect(uncertain.decision).toBe("defer");
    expect(uncertain.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "invalid-imported-bash-function" }));
  });

  test("export -f makes a local function available to a fresh Bash child", () => {
    const result = analyzeBashWithPolicies({
      source: "helm(){ gh exported; }; export -f helm; bash -c 'helm list'",
      initialEnvironment: completePolicyInitialEnvironment({}), policies: [policy("permission", () => allow)],
    });
    expect(result.events).toContainEqual(expect.objectContaining({ kind: "invocation", executable: { kind: "known", value: "gh" }, argv: [{ kind: "known", value: "exported" }] }));
    expect(result.events).not.toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "invalid-imported-bash-function" }));
  });

  test("property: external wrapper spellings never run an inherited Bash function", () => {
    for (let index = 0; index < 64; index++) {
      const name = `tool_${index}`;
      const initialEnvironment = completePolicyInitialEnvironment({ [`BASH_FUNC_${name}%%`]: "() { gh shadowed; }" });
      for (const source of [`strace -- ${name} argument`, `env ${name} argument`, `timeout 5s ${name} argument`, `exec ${name} argument`]) {
        const result = analyzeBashWithPolicies({ source, initialEnvironment, policies: [policy("permission", () => allow)] });
        const child = result.events.find((event) => event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === name);
        expect(child, source).toMatchObject({ kind: "invocation", executionTarget: "external-path" });
        expect(result.events.some((event) => event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "gh"), source).toBeFalse();
      }
    }
  });

  test("property: imported definition admission agrees with Bash for supported and malformed encodings", () => {
    for (let index = 0; index < 32; index++) {
      const name = `tool_${index}`;
      const key = `BASH_FUNC_${name}%%`;
      for (const [body, valid] of [[`(){ printf '%s' '${index}'; }`, false],
        [`() { printf '%s' '${index}'; }`, true], ["not-a-function", false],
        ["() { :; }; printf unexpected", false]] as const) {
        const shell = spawnSync("bash", ["--noprofile", "--norc", "-c", `declare -F ${name} >/dev/null`], {
          env: { PATH: process.env.PATH ?? "", [key]: body }, encoding: "utf8",
        });
        expect(shell.status === 0, `${key} fixture ${index}`).toBe(valid);
        const result = analyzeBashWithPolicies({
          source: `${name} argument`, initialEnvironment: completePolicyInitialEnvironment({ [key]: body }),
          policies: [policy("permission", () => allow)],
        });
        expect(result.events.some((event) => event.kind === "execution-gap" && event.reason === "invalid-imported-bash-function"), `${key} fixture ${index}`).toBe(!valid);
      }
    }
  });

  test("a path-qualified builtin spelling is an external executable, while a builtin has no filesystem target", () => {
    const result = analyzeBashWithPolicies({ source: "command -v helm; /usr/bin/command -v helm", initialEnvironment: completePolicyInitialEnvironment({}), policies: [policy("permission", () => allow)] });
    const events = result.events.filter((event) => event.kind === "invocation");
    expect(events[0]).toMatchObject({ executionTarget: "builtin", executableIdentity: { qualification: "incomplete", basename: "command", failure: { kind: "not-external" } } });
    expect(events[1]).toMatchObject({ executionTarget: "external-path", executable: { kind: "known", value: "/usr/bin/command" } });
  });

  test("retains opaque children as gaps and does not hide a later deny", () => {
    const result = analyzeBashWithPolicies({
      source: "CANARY=gap-value exec --unknown opaque-canary; gh later",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [
        policy("permission", () => allow),
        policy("guard", (event) => event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "gh" ? deny : { kind: "ignore" }),
      ],
    });

    expect(result.events).toContainEqual(expect.objectContaining({
      kind: "execution-gap",
      reason: "structural-parse-failure",
      environment: { CANARY: { kind: "known", value: "gap-value" } },
      provenance: { route: ["direct"] },
      inPipeline: false,
      processEffect: "unknown",
      span: { start: 0, end: "CANARY=gap-value exec --unknown opaque-canary".length },
    }));
    expect(result.decision).toBe("deny");
  });

  test("retains pipeline context for every reachable pipeline invocation", () => {
    const result = analyzeBashWithPolicies({
      source: "printf value | gh status",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(result.events)).toMatchObject({ inPipeline: true, processEffect: "none" });
  });

  test("property: deterministic repeated projection preserves every event field", () => {
    for (let index = 0; index < 64; index++) {
      const value = `value-${index}`;
      const result = analyzeBashWithPolicies({
        source: `env -i CANARY=${value} gh argument-${index}`,
        initialEnvironment: { kind: "verified", values: {} },
        policies: [policy("permission", () => allow)],
      });
      const event = result.events.find((candidate) => candidate.kind === "invocation" && candidate.executable.kind === "known" && candidate.executable.value === "gh");
      expect(event, String(index)).toMatchObject({
        environment: { CANARY: { kind: "known", value } },
        argv: [{ kind: "known", value: `argument-${index}` }],
        provenance: { route: ["direct", "transparent-wrapper"] },
        processEffect: "exec-replace",
      });
    }
  });
});

function policy(layer: "guard" | "permission", evaluate: (event: BashPolicyEvent) => ReturnType<ValidatedBashPolicy["evaluate"]>): ValidatedBashPolicy {
  return Object.freeze({
    source: Object.freeze({ canonicalPath: `/policies/${layer}.policy.mjs` }),
    layer,
    select: Object.freeze([]),
    evaluate,
  }) as ValidatedBashPolicy;
}

function onlyInvocation(events: readonly BashPolicyEvent[]) {
  const event = events.find((candidate) => candidate.kind === "invocation" && candidate.executable.kind === "known" && candidate.executable.value === "gh");
  if (!event || event.kind !== "invocation") throw new Error("Expected a gh invocation event");
  return event;
}
