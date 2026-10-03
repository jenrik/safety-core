import { beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  analyzeBashWithPolicies,
  type BashPolicyEvent,
  completePolicyInitialEnvironment,
  type InvocationView,
  initBundledBashParser,
} from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const envPath = new URL("../policies/dsl/env-command.policy.json", import.meta.url);
const commandPath = new URL("../policies/dsl/command-discovery.policy.json", import.meta.url);
const envPolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(envPath, "utf8"))),
  envPath.pathname,
);
const commandPolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(commandPath, "utf8"))),
  commandPath.pathname,
);

beforeAll(async () => {
  await initBundledBashParser();
});

function directDecision(argv: readonly string[]): string {
  const event: InvocationView = {
    kind: "invocation",
    executable: { kind: "known", value: "env" },
    executionTarget: "external-path",
    executableIdentity: {
      qualification: "incomplete",
      spelling: "env",
      basename: "env",
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: argv.map((value) => ({ kind: "known" as const, value })),
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  };
  return envPolicy.evaluate(event).kind;
}

function analyze(source: string) {
  return analyzeBashWithPolicies({
    source,
    initialEnvironment: completePolicyInitialEnvironment({}),
    policies: [envPolicy, commandPolicy],
  });
}

function invocationNames(result: ReturnType<typeof analyze>): string[] {
  return result.events.flatMap((event) => (isKnownInvocation(event) ? [event.executable.value] : []));
}

function envEvent(result: ReturnType<typeof analyze>): InvocationView {
  const event = result.events.find(isEnvInvocation);
  if (!event) throw new Error("missing env invocation");
  return event;
}

function isKnownInvocation(
  event: BashPolicyEvent,
): event is InvocationView & { readonly executable: { readonly kind: "known"; readonly value: string } } {
  return event.kind === "invocation" && event.executable?.kind === "known";
}

function isEnvInvocation(event: BashPolicyEvent): event is InvocationView {
  return isKnownInvocation(event) && event.executable.value === "env";
}

describe("env command DSL policy", () => {
  test("defers every assignment-only environment print form, including after --", () => {
    for (const argv of [
      [],
      ["MODE=test"],
      ["A-B=y"],
      ["1X=y"],
      ["A.B=y"],
      ["=y"],
      ["--", "MODE=test"],
      ["--", "A-B=y"],
    ]) {
      expect(directDecision(argv), argv.join(" ")).toBe("defer");
    }
  });

  test("permits a child command after GNU assignment operands before or after --", () => {
    for (const argv of [
      ["MODE=test", "command", "-v", "tool"],
      ["A-B=y", "command", "-v", "tool"],
      ["1X=y", "command", "-v", "tool"],
      ["=y", "command", "-v", "tool"],
      ["--", "MODE=test", "command", "-v", "tool"],
      ["--", "A-B=y", "command", "-v", "tool"],
    ]) {
      expect(directDecision(argv), argv.join(" ")).toBe("allow");
    }
  });

  test("models assignments after -- before dispatching the actual child", () => {
    const result = analyze("env -- MODE=test command -v tool");
    expect(result.decision).toBe("allow");
    expect(invocationNames(result)).toEqual(["env", "command"]);
    expect(envPolicy.evaluate(envEvent(result)).kind).toBe("allow");
  });

  test("uses declarative option parsing for attached short values without auxiliary states", () => {
    const noCommand = analyze("env -iuOLD -i");
    expect(directDecision(["-iuOLD", "-i"])).toBe("defer");
    expect(noCommand.decision).toBe("defer");
    expect(invocationNames(noCommand)).toEqual(["env"]);
    expect(envPolicy.evaluate(envEvent(noCommand)).kind).toBe("defer");

    const command = analyze("env -iuOLD -i command -v tool");
    expect(command.decision).toBe("allow");
    expect(invocationNames(command)).toEqual(["env", "command"]);
    expect(envPolicy.evaluate(envEvent(command)).kind).toBe("allow");

    expect(directDecision(["-z", "command", "-v", "tool"])).toBe("defer");
  });

  test("ends env option parsing at the first assignment operand", () => {
    const children = ["--", "-", "-i", "-iv", "--ignore-environment", "-u"];
    for (const assignment of ["MODE=test", "=y"]) {
      for (const child of children) {
        const source = `env ${assignment} ${child}`;
        const result = analyze(source);
        expect(directDecision([assignment, child]), source).toBe("allow");
        expect(result.decision, source).toBe("defer");
        expect(invocationNames(result), source).toEqual(["env", child]);
        expect(envPolicy.evaluate(envEvent(result)).kind, source).toBe("allow");
      }
    }

    const laterAssignment = analyze("env MODE=test --unset=OLD command -v tool");
    expect(laterAssignment.decision).toBe("allow");
    expect(invocationNames(laterAssignment)).toEqual(["env", "command"]);
    expect(envPolicy.evaluate(envEvent(laterAssignment)).kind).toBe("allow");
  });

  test("keeps assignment-only forms prompt-gated instead of fabricating a child", () => {
    for (const source of [
      "env MODE=test",
      "env A-B=y",
      "env 1X=y",
      "env A.B=y",
      "env =y",
      "env -- MODE=test",
      "env -- A-B=y",
    ]) {
      const result = analyze(source);
      expect(result.decision, source).toBe("defer");
      expect(invocationNames(result), source).toEqual(["env"]);
      expect(envPolicy.evaluate(envEvent(result)).kind, source).toBe("defer");
    }
  });

  test("defers imported and local Bash functions named env before analyzing their bodies", () => {
    for (const [source, initialEnvironment] of [
      ["env command -v tool", completePolicyInitialEnvironment({ "BASH_FUNC_env%%": "() { command -v tool; }" })],
      ["env() { command -v tool; }; env command -v tool", completePolicyInitialEnvironment({})],
    ] as const) {
      const result = analyzeBashWithPolicies({ source, initialEnvironment, policies: [envPolicy, commandPolicy] });
      const gap = result.events.find(
        (event) => event.kind === "execution-gap" && event.reason === "shadowed-env-function",
      );
      expect(gap, source).toBeDefined();
      expect(result.decision, source).toBe("defer");
      expect(invocationNames(result), source).toEqual(["command"]);
    }
  });

  test("property: every supported short cluster preserves the direct child boundary", () => {
    const flagClusters = new Set<string>();
    const visit = (prefix: string, remaining: readonly string[]) => {
      if (prefix) flagClusters.add(prefix);
      for (let index = 0; index < remaining.length; index++) {
        visit(`${prefix}${remaining[index]!}`, [...remaining.slice(0, index), ...remaining.slice(index + 1)]);
      }
    };
    visit("", ["i", "0", "v"]);

    for (const flags of flagClusters) {
      const source = `env -${flags} command -v tool`;
      const result = analyze(source);
      expect(directDecision([`-${flags}`, "command", "-v", "tool"]), source).toBe("allow");
      expect(result.decision, source).toBe("allow");
      expect(invocationNames(result), source).toEqual(["env", "command"]);
    }

    for (const flags of ["", ...flagClusters]) {
      for (const valueOption of ["u", "C", "a"]) {
        const attached = `-${flags}${valueOption}value`;
        const separate = `-${flags}${valueOption}`;
        for (const argv of [
          [attached, "command", "-v", "tool"],
          [separate, "value", "command", "-v", "tool"],
        ]) {
          const source = `env ${argv.join(" ")}`;
          const result = analyze(source);
          expect(directDecision(argv), source).toBe("allow");
          expect(result.decision, source).toBe("allow");
          expect(invocationNames(result), source).toEqual(["env", "command"]);
        }
      }
    }

    for (const cluster of ["-S", "-iS", "-Si", "-0Sv", "-vS", "-Suvalue"]) {
      expect(directDecision([cluster, "command", "-v", "tool"]), cluster).toBe("defer");
    }
  });

  test("property: assignment spelling and placement preserve the no-dump boundary", () => {
    for (let index = 0; index < 128; index++) {
      const assignment = [
        `MODE_${index}=value-${index}`,
        `A-${index}=value-${index}`,
        `${index}X=value-${index}`,
        `A.${index}=value-${index}`,
        `=value-${index}`,
      ][index % 5]!;
      for (const prefix of ["", "-- "]) {
        const noCommand = analyze(`env ${prefix}${assignment}`);
        expect(noCommand.decision, `${prefix}${assignment}`).toBe("defer");
        expect(invocationNames(noCommand), `${prefix}${assignment}`).toEqual(["env"]);

        const command = analyze(`env ${prefix}${assignment} command -v tool`);
        expect(command.decision, `${prefix}${assignment} command`).toBe("allow");
        expect(invocationNames(command), `${prefix}${assignment} command`).toEqual(["env", "command"]);
      }
    }
  });

  test("property: modifier-looking operands after assignments are child commands", () => {
    const children = ["--", "-", "-i", "-iv", "--ignore-environment", "-u"];
    for (let index = 0; index < 128; index++) {
      const assignment = [
        `MODE_${index}=value-${index}`,
        `A-${index}=value-${index}`,
        `${index}X=value-${index}`,
        `A.${index}=value-${index}`,
        `=value-${index}`,
      ][index % 5]!;
      const child = children[index % children.length]!;
      const source = `env ${assignment} ${child}`;
      const result = analyze(source);
      expect(directDecision([assignment, child]), source).toBe("allow");
      expect(result.decision, source).toBe("defer");
      expect(invocationNames(result), source).toEqual(["env", child]);
      expect(envPolicy.evaluate(envEvent(result)).kind, source).toBe("allow");
    }
  });
});
