import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";
import {
  createCommandRegistry,
  dispatchCommand,
  ignorePolicy,
  observePolicy,
  type InvocationCursor,
  type PolicyObserver,
} from "../src/bash/dispatch.ts";
import { fromInitialEnvironment, unknown } from "../src/bash/environment.ts";
import { httpHandlers } from "../src/bash/handlers/http.ts";
import { readerHandlers } from "../src/bash/handlers/readers.ts";
import { safe } from "../src/bash/outcome.ts";
import { runSteps } from "../src/bash/runner.ts";
import { structuralHandlers } from "../src/bash/handlers/registry.ts";
import { HTTP_TOOLS, READING_COMMANDS } from "../src/patterns.ts";
import { type BashDispatchRequest, type BashDispatchResult, walkProgram } from "../src/bash/walker.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-dispatch-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(
    join(process.cwd(), "node_modules", "web-tree-sitter"),
    join(wasmDir, "node_modules", "web-tree-sitter"),
  );
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("named Bash command dispatch", () => {
  test("routes a strace child to only the registered executable handler", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("strace -f gh pr create --repo github.com/acme/widgets", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations).toHaveLength(1);
    expect(invocations[0]).toMatchObject({
      invocation: {
        executable: { kind: "known", value: "gh" },
        argv: [
          { kind: "known", value: "pr" },
          { kind: "known", value: "create" },
          { kind: "known", value: "--repo" },
          { kind: "known", value: "github.com/acme/widgets" },
        ],
      },
      index: 0,
    });
  });

  test("gives every named handler a frozen cursor and frozen options", () => {
    let cursor: InvocationCursor | undefined;
    const result = analyze("gh pr create", [recordingHandler("gh", [], (received) => { cursor = received; })]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(cursor).toBeDefined();
    expect(Object.isFrozen(cursor)).toBeTrue();
    expect(Object.isFrozen(cursor?.invocation)).toBeTrue();
    expect(Object.isFrozen(cursor?.options)).toBeTrue();
  });

  test("registers only structural handlers by default", () => {
    const registry = createCommandRegistry();

    expect(registry.resolve("env").name).toBe("env");
    expect(registry.resolve("sh").name).toBe("sh");
    expect(registry.resolve("cat").name).toBe("unknown-command");
    expect(registry.resolve("curl").name).toBe("unknown-command");
    expect(registry.resolve("gh").name).toBe("unknown-command");
  });

  test("property: every structural handler is resolved by the default registry", () => {
    const registry = createCommandRegistry();
    for (const handler of structuralHandlers) {
      expect(registry.resolve(handler.name).name).toBe(handler.name);
    }
  });

  test("property: command-policy facades cover exactly their configured command sets", () => {
    expect(new Set(readerHandlers.map((handler) => handler.name))).toEqual(READING_COMMANDS);
    expect(new Set(httpHandlers.map((handler) => handler.name))).toEqual(HTTP_TOOLS);
  });

  test("composes a caller policy handler with mandatory wrapper recursion", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("strace -f denied-command", [
      recordingHandler("strace", invocations),
      denyHandler("denied-command"),
    ]);

    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
    expect(invocations).toHaveLength(1);
    expect(invocations[0]?.invocation.executable).toEqual({ kind: "known", value: "strace" });
  });

  test.each([
    "strace --output=trace.log denied-command",
    "strace -fo trace.log denied-command",
    "timeout --verbose 5s denied-command",
    "timeout -k1s 5s denied-command",
    "timeout -vk1s 5s denied-command",
    "env --argv0=alias denied-command",
    "env -iuHOME denied-command",
    "env -S 'denied-command'",
    "exec -cl denied-command",
    "nice -5 denied-command",
    "setsid -fw denied-command",
    "doas -nu root denied-command",
    "xargs denied-command",
    "xargs sh -c 'denied-command'",
    "find . -maxdepth 0 -exec denied-command {} \\;",
    "find . -exec sh -c 'denied-command' _ {} \\;",
    "eval -- 'denied-command'",
    "fish -C 'denied-command' -c true",
    "fish --init-command 'denied-command' --command true",
    "fish -C true -c 'denied-command'",
    "fish -d parser -c 'denied-command'",
    "fish --profile-startup /tmp/profile -c 'denied-command'",
    "fish --init-cmd 'denied-command' -c true",
    "fish --no-config -c 'denied-command'",
    "fish --interactive -c 'denied-command'",
    "fish --login -c 'denied-command'",
    "fish --private -c 'denied-command'",
    "fish --print-rusage-self -c 'denied-command'",
    "fish -Nd parser -c 'denied-command'",
    "sudo denied-command",
    "sudo -u root -- denied-command",
    "sudo -k denied-command",
  ])("preserves a child denial through documented wrapper options: %s", (source) => {
    expect(analyze(source, [denyHandler("denied-command")]).completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("property: documented wrapper option orderings preserve child denials", () => {
    const random = lcg(0x51a7_2ce9);
    const wrappers = [
      { prefix: "strace", options: ["--follow-forks", "--output=trace.log", "--trace=process"], suffix: "denied-command" },
      { prefix: "timeout", options: ["--verbose", "--foreground", "--kill-after=1s"], suffix: "5s denied-command" },
      { prefix: "env", options: ["--argv0=alias", "--ignore-environment", "MODE=test"], suffix: "denied-command" },
      { prefix: "strace", options: ["-fo trace.log", "--trace=process"], suffix: "denied-command" },
      { prefix: "timeout", options: ["-v", "-f", "-k1s"], suffix: "5s denied-command" },
      { prefix: "timeout", options: ["-vk1s", "-p"], suffix: "5s denied-command" },
      { prefix: "env", options: ["-iuHOME", "-aalias", "MODE=test"], suffix: "denied-command" },
      { prefix: "exec", options: ["-cl"], suffix: "denied-command" },
      { prefix: "nice", options: ["-5", "-n 2"], suffix: "denied-command" },
      { prefix: "setsid", options: ["-fw", "-c"], suffix: "denied-command" },
      { prefix: "doas", options: ["-nu root"], suffix: "denied-command" },
      { prefix: "xargs", options: ["-r", "-n1", "-t"], suffix: "denied-command" },
      { prefix: "sudo", options: ["-n", "-u root", "-D /tmp"], suffix: "-- denied-command" },
    ];
    for (const wrapper of wrappers) {
      for (let iteration = 0; iteration < 32; iteration++) {
        const source = `${wrapper.prefix} ${shuffle(wrapper.options, random).join(" ")} ${wrapper.suffix}`;
        expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
      }
    }
  });

  test.each([
    "bash -lc 'denied-command'",
    "bash -l -c 'denied-command'",
    "bash -O extglob -c 'denied-command'",
    "bash -euo pipefail -c 'denied-command'",
    "bash -euxo pipefail -c 'denied-command'",
    "bash +O extglob -c 'denied-command'",
    "bash -coo pipefail nounset 'denied-command'",
    "bash -c \"denied-command\"",
    "bash -Ec 'denied-command'",
    "bash -Tc 'denied-command'",
    "bash --debug -c 'denied-command'",
    "bash --pretty-print -c 'denied-command'",
    "zsh -dfc 'denied-command'",
    "zsh --no-rcs -c 'denied-command'",
    "zsh --no-global-rcs -c 'denied-command'",
    "zsh --no_rcs -c 'denied-command'",
    "zsh --GLOBAL_RCS -c 'denied-command'",
    "zsh +-RCS -c 'denied-command'",
    "zsh +-no-RCS -c 'denied-command'",
  ])("preserves nested denials through common shell option forms: %s", (source) => {
    expect(analyze(source, [denyHandler("denied-command")]).completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("property: shell login option orderings preserve nested denials", () => {
    const random = lcg(0x7a31_9d04);
    for (let iteration = 0; iteration < 64; iteration++) {
      const options = shuffle(["-l", "--noprofile", "-x", "-euo pipefail", "+O extglob"], random);
      const source = `bash ${options.join(" ")} -c 'denied-command'`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("property: non-empty double-quoted scripts preserve nested denials", () => {
    for (let iteration = 0; iteration < 64; iteration++) {
      const source = `bash -c "denied-command argument-${iteration}"`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("property: interpreter short-flag clusters preserve nested denials", () => {
    const random = lcg(0x18c4_a72f);
    for (let iteration = 0; iteration < 64; iteration++) {
      const flags = shuffle(["d", "f", "E", "T", "x"], random).join("");
      const source = `zsh -${flags}c 'denied-command'`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("property: zsh named options preserve nested denials", () => {
    for (const option of ["--no-rcs", "--no-global-rcs", "--no_rcs", "--GLOBAL_RCS", "+-RCS", "+-no-RCS", "--rcs", "--global-rcs", "--interactive", "--login"]) {
      const source = `zsh ${option} -c 'denied-command'`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("uses unknown-command only when every matching policy observer ignores the invocation", () => {
    const ignored = analyze("gh pr list", [{
      name: "gh",
      observe: () => ignorePolicy(),
    }]);
    const observed = analyze("gh pr list", [recordingHandler("gh", [])]);

    expect(ignored.completed.verdict).toEqual({ kind: "neutral" });
    expect(observed.completed.verdict).toEqual({ kind: "allow" });
  });

  test("schedules and observes each literal shell child exactly once", () => {
    let observations = 0;
    const result = analyze("bash -c 'gh pr create --repo github.com/acme/widgets --fill'", [{
      name: "gh",
      observe: () => {
        observations++;
        return observePolicy(safe());
      },
    }]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(observations).toBe(1);
  });

  test("carries route-only provenance without retaining materialized source values", () => {
    const marker = "opaque-provenance-canary";
    const routes: Record<string, unknown> = {};
    const observeRoute = (name: string): PolicyObserver => ({
      name: "gh",
      observe: (_cursor, context) => {
        routes[name] = context.provenance;
        return observePolicy(safe());
      },
    });

    for (const [name, source] of [
      ["direct", "gh pr create"],
      ["wrapper", "strace gh pr create"],
      ["eval", "eval 'gh pr create'"],
      ["shell", "bash -c 'gh pr create'"],
      ["binding", `SCRIPT='gh pr create ${marker}'; bash -c "$SCRIPT"`],
    ] as const) analyze(source, [observeRoute(name)]);

    expect(routes).toEqual({
      direct: { route: ["direct"] },
      wrapper: { route: ["direct", "transparent-wrapper"] },
      eval: { route: ["direct", "eval"] },
      shell: { route: ["direct", "shell-command"] },
      binding: { route: ["direct", "shell-command", "binding-derived-script"] },
    });
    expect(JSON.stringify(routes)).not.toContain(marker);
  });

  test.each([
    ["env -i MODE=test gh pr create", "gh", ["pr", "create"], "neutral"],
    ["command -p gh pr create", "gh", ["pr", "create"], "allow"],
    ["doas -n -u root gh pr create", "gh", ["pr", "create"], "neutral"],
    ["exec -a check gh pr create", "gh", ["pr", "create"], "neutral"],
    ["nice -n 5 gh pr create", "gh", ["pr", "create"], "allow"],
    ["nice -n5 gh pr create", "gh", ["pr", "create"], "allow"],
    ["nohup -- gh pr create", "gh", ["pr", "create"], "neutral"],
    ["setsid --fork gh pr create", "gh", ["pr", "create"], "allow"],
    ["stdbuf -oL gh pr create", "gh", ["pr", "create"], "allow"],
    ["timeout -k 5s 10s gh pr create", "gh", ["pr", "create"], "allow"],
    ["strace -f -o trace.log gh pr create", "gh", ["pr", "create"], "neutral"],
  ] as const)("consumes supported wrapper flags before dispatching %s", (source, executable, argv, verdict) => {
    const invocations: InvocationCursor[] = [];
    const result = analyze(source, [recordingHandler(executable, invocations)]);

    expect(result.completed.verdict).toEqual({ kind: verdict });
    expect(invocations.map(renderInvocation)).toEqual([[executable, ...argv]]);
  });

  test.each([
    "/tmp/nice gh pr create",
    "LD_PRELOAD=/tmp/instrumentation.so nice gh pr create",
    "nice gh pr create > response.json",
    "env -i gh pr create",
    "env --chdir=/tmp gh pr create",
    "doas -n gh pr create",
    "exec -c gh pr create",
    "nohup gh pr create",
    "strace -o trace.log gh pr create",
    "strace -u root gh pr create",
    "strace -E NAME=value gh pr create",
  ])("taints wrapper-envelope side effects while preserving child inspection: %s", (source) => {
    const invocations: InvocationCursor[] = [];
    const result = analyze(source, [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations.map(renderInvocation)).toEqual([["gh", "pr", "create"]]);
  });

  test("does not treat doas shell mode as a transparent child invocation", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("doas -s gh pr create", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations).toHaveLength(0);
  });

  test("property: doas configuration checks never expose a child invocation", () => {
    const random = lcg(0x4fca_7e12);
    for (let iteration = 0; iteration < 64; iteration++) {
      const invocations: InvocationCursor[] = [];
      const flags = shuffle(["-n", "-u root"], random).join(" ");
      const result = analyze(`doas ${flags} -C config-${random()} gh pr create`, [recordingHandler("gh", invocations)]);

      expect(result.completed.verdict).toEqual({ kind: "allow" });
      expect(invocations).toHaveLength(0);
    }
  });

  test("keeps a doas configuration check with no config path neutral", () => {
    const result = directWrapperDispatch("doas", ["-C"]);

    expect(dispatchOutcome(result.result)).toMatchObject({ kind: "indeterminate" });
    expect(result.scheduled).toHaveLength(0);
  });

  test("walks a statically known sh -c script only through continueWith", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("sh -c 'gh pr create --repo github.com/acme/widgets'", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations.map(renderInvocation)).toEqual([[
      "gh", "pr", "create", "--repo", "github.com/acme/widgets",
    ]]);
  });

  test("clears omitted positional parameters for sh -c beneath a function call", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("outer(){ sh -c 'run \"$1\" \"$2\"'; }; outer caller-one caller-two", [recordingHandler("run", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations.map(renderInvocation)).toEqual([["run", "", ""]]);
  });

  test.each([
    "bash -c 'gh pr create' > result.txt",
    "/bin/bash -c 'gh pr create'",
    "BASH_ENV=setup.sh bash -c 'gh pr create'",
    "eval 'gh pr create' > result.txt",
  ])("keeps interpreter envelope effects prompt-gated while inspecting the nested script: %s", (source) => {
    const invocations: InvocationCursor[] = [];
    const result = analyze(source, [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations.map(renderInvocation)).toEqual([["gh", "pr", "create"]]);
  });

  test.each([
    "sh -xc denied-command",
    "sh -o xtrace -c denied-command",
  ])("walks %s rather than allowing a combined or value-taking shell option", (source) => {
    const result = analyze(source, [denyHandler("denied-command")]);

    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("returns neutral for an ambient sh -c script rather than treating it as an executable", () => {
    const result = analyze("sh -c '$COMMAND'", [], { COMMAND: unknown({ kind: "ambient" }) });

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
  });

  test("leaves an unregistered executable neutral through unknown-command", () => {
    const result = analyze("unregistered --write", []);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(result.completed.evidence).toContainEqual({
      kind: "indeterminate",
      span: { start: 0, end: "unregistered --write".length },
    });
  });

  test("dispatches static find and xargs command templates while tainting dynamic input", () => {
    const invocations: InvocationCursor[] = [];
    const find = analyze("find . -type f -exec gh pr create --repo github.com/acme/widgets \\;", [recordingHandler("gh", invocations)]);
    const xargs = analyze("xargs -n 1 gh pr create", [recordingHandler("gh", invocations)]);

    expect(find.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations.map(renderInvocation)).toEqual([
      ["gh", "pr", "create", "--repo", "github.com/acme/widgets"],
      ["gh", "pr", "create"],
    ]);
    expect(xargs.completed.verdict).toEqual({ kind: "neutral" });
  });

  test("property: find placeholders preserve explicit child denials at every argument boundary", () => {
    for (let index = 0; index < 64; index++) {
      const arguments_ = Array.from({ length: index % 8 }, (_, argument) => `arg-${argument}`);
      const source = `find . -maxdepth 0 -exec denied-command ${arguments_.join(" ")} {} \\;`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("walks every statically closed find -exec action", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("find . -exec allowed-command \\; -exec denied-command \\;", [
      recordingHandler("allowed-command", invocations),
      denyHandler("denied-command"),
    ]);

    expect(invocations.map(renderInvocation)).toEqual([["allowed-command"]]);
    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("keeps nested indeterminacy and nested-depth failures sticky through wrapper chains", () => {
    const indeterminate = analyze("strace -f sh -c '$UNKNOWN'", [], { UNKNOWN: unknown({ kind: "ambient" }) });
    const exhausted = analyze("strace -f sh -c 'allowed-command'", [recordingHandler("allowed-command", [])], fromInitialEnvironment({}, {
      nestedScriptDepth: 0,
    }));

    expect(indeterminate.completed.verdict).toEqual({ kind: "neutral" });
    expect(exhausted.completed.outcome).toMatchObject({ kind: "failure", budget: "max-nested-script-depth" });
  });

  test("property: wrapper flag permutations preserve the same known child invocation", () => {
    const random = lcg(0x2c4d6e8f);
    const flags = ["-f", "-o trace.log", "-e trace=process"];

    for (let iteration = 0; iteration < 64; iteration++) {
      const invocations: InvocationCursor[] = [];
      const permutation = shuffle(flags, random);
      const result = analyze(`strace ${permutation.join(" ")} gh pr create`, [recordingHandler("gh", invocations)]);

      expect(result.completed.verdict).toEqual({ kind: "neutral" });
      expect(invocations.map(renderInvocation)).toEqual([["gh", "pr", "create"]]);
    }
  });

  test("property: transparent wrappers preserve one child observation and redacted provenance", () => {
    const wrappers = [
      { wrap: (child: string) => `env -i ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `command -p ${child}`, verdict: "allow" },
      { wrap: (child: string) => `doas -n -u root ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `exec -a check ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `nice -n 5 ${child}`, verdict: "allow" },
      { wrap: (child: string) => `nohup -- ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `setsid --fork ${child}`, verdict: "allow" },
      { wrap: (child: string) => `stdbuf -oL ${child}`, verdict: "allow" },
      { wrap: (child: string) => `timeout 5s ${child}`, verdict: "allow" },
      { wrap: (child: string) => `strace -f ${child}`, verdict: "allow" },
      { wrap: (child: string) => `find . -exec ${child} \\;`, verdict: "allow" },
    ];
    for (const { wrap, verdict } of wrappers) {
      let observations = 0;
      let provenance: unknown;
      const result = analyze(wrap("gh pr create"), [{
        name: "gh",
        observe: (_cursor, context) => {
          observations++;
          provenance = context.provenance;
          return observePolicy(safe());
        },
      }]);
      expect(result.completed.verdict, wrap.name).toEqual({ kind: verdict });
      expect(observations, wrap.name).toBe(1);
      expect(provenance, wrap.name).toEqual({ route: ["direct", "transparent-wrapper"] });
    }
  });

  test("property: audited flags for every child-executing wrapper preserve its known child", () => {
    const random = lcg(0x4b1d7a2c);
    const wrappers = [
      { name: "env", prefix: "env", flags: ["-i", "MODE=test"], child: "gh pr create", verdict: "neutral" },
      { name: "command", prefix: "command", flags: ["-p"], child: "gh pr create", verdict: "allow" },
      { name: "doas", prefix: "doas", flags: ["-n", "-u root"], child: "gh pr create", verdict: "neutral" },
      { name: "exec", prefix: "exec", flags: ["-c", "-l", "-a name"], child: "gh pr create", verdict: "neutral" },
      { name: "nice", prefix: "nice", flags: ["-n 5"], child: "gh pr create", verdict: "allow" },
      { name: "nohup", prefix: "nohup", flags: ["--"], child: "gh pr create", verdict: "neutral" },
      { name: "setsid", prefix: "setsid", flags: ["--fork", "--wait"], child: "gh pr create", verdict: "allow" },
      { name: "stdbuf", prefix: "stdbuf", flags: ["-oL", "-e0"], child: "gh pr create", verdict: "allow" },
      { name: "timeout", prefix: "timeout", flags: ["-k 5s", "--foreground"], child: "10s gh pr create", verdict: "allow" },
      { name: "strace", prefix: "strace", flags: ["-f", "-o trace.log", "-e trace=process"], child: "gh pr create", verdict: "neutral" },
      { name: "sh", prefix: "sh", flags: ["-x", "-v"], child: "-c 'gh pr create'", verdict: "neutral" },
    ];

    for (const wrapper of wrappers) {
      for (let iteration = 0; iteration < 32; iteration++) {
        const invocations: InvocationCursor[] = [];
        const flags = shuffle(wrapper.flags, random).join(" ");
        const source = `${wrapper.prefix} ${flags} ${wrapper.child}`;
        const result = analyze(source, [recordingHandler("gh", invocations)]);

        expect(result.completed.verdict, `${wrapper.name}: ${source}`).toEqual({ kind: wrapper.verdict });
        expect(invocations.map(renderInvocation), `${wrapper.name}: ${source}`).toEqual([["gh", "pr", "create"]]);
      }
    }
  });

  test("property: an unknown child word at every wrapper boundary is never allow", () => {
    const wrappers = [
      { wrap: (child: string) => `env -i ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `command -p ${child}`, verdict: "allow" },
      { wrap: (child: string) => `doas -n -u root ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `exec -a name ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `nice -n 5 ${child}`, verdict: "allow" },
      { wrap: (child: string) => `nohup -- ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `setsid --fork ${child}`, verdict: "allow" },
      { wrap: (child: string) => `stdbuf -oL ${child}`, verdict: "allow" },
      { wrap: (child: string) => `timeout 1s ${child}`, verdict: "allow" },
      { wrap: (child: string) => `strace -f ${child}`, verdict: "allow" },
      { wrap: (child: string) => `sh -c ${child}`, verdict: "neutral" },
      { wrap: (child: string) => `find . -exec ${child} \\;`, verdict: "allow" },
    ];

    for (const { wrap, verdict } of wrappers) {
      const baselineInvocations: InvocationCursor[] = [];
      const baseline = analyze(wrap("gh"), [recordingHandler("gh", baselineInvocations)]);
      const result = analyze(wrap('"$UNKNOWN"'), [recordingHandler("gh", [])], { UNKNOWN: unknown({ kind: "ambient" }) });

      expect(baseline.completed.verdict, wrap.name).toEqual({ kind: verdict });
      expect(baselineInvocations.map(renderInvocation), wrap.name).toEqual([["gh"]]);
      expect(result.completed.verdict, wrap.name).toEqual({ kind: "neutral" });
    }
  });

  test("property: direct wrapper results retain an unknown at every audited boundary before walker evidence", () => {
    const wrappers = [
      ["env", ["-i", "MODE=test", "gh"], "indeterminate"],
      ["env", ["-u", "NAME", "gh"], "indeterminate"],
      ["command", ["-p", "gh"], "safe"],
      ["doas", ["-n", "-u", "root", "gh"], "indeterminate"],
      ["exec", ["-a", "name", "gh"], "indeterminate"],
      ["nice", ["-n", "5", "gh"], "safe"],
      ["nohup", ["--", "gh"], "indeterminate"],
      ["setsid", ["--fork", "gh"], "safe"],
      ["stdbuf", ["-oL", "gh"], "safe"],
      ["stdbuf", ["-o", "L", "gh"], "safe"],
      ["timeout", ["-k", "5s", "10s", "gh"], "safe"],
      ["strace", ["-f", "gh"], "safe"],
      ["strace", ["-o", "trace.log", "gh"], "indeterminate"],
      ["sh", ["-c", "gh"], "indeterminate"],
      ["find", [".", "-exec", "gh", ";"], "safe"],
    ] as const;

    for (const [executable, argv, outcome] of wrappers) {
      const baseline = directWrapperDispatch(executable, argv);
      expect(dispatchOutcome(baseline.result), executable).toMatchObject({ kind: outcome });
      expect(baseline.scheduled, executable).toHaveLength(1);

      for (let boundary = 0; boundary < argv.length; boundary++) {
        const result = directWrapperDispatch(executable, [
          ...argv.slice(0, boundary),
          undefined,
          ...argv.slice(boundary),
        ]);
        expect(dispatchOutcome(result.result), `${executable}:${boundary}`).toMatchObject({ kind: "indeterminate" });
      }
    }
  });

  test("routes every registered executable name only to its matching caller handler", () => {
    const names = ["env", "command", "doas", "exec", "nice", "nohup", "setsid", "stdbuf", "timeout", "strace", "sudo", "sudoedit", "xargs", "find", "sh"];
    const invocations: InvocationCursor[] = [];
    const handlers = names.map((name) => recordingHandler(name, invocations));

    for (const name of names) analyze(name, handlers);

    expect(invocations.map((cursor) => cursor.invocation.executable)).toEqual(names.map((name) => ({ kind: "known", value: name })));
  });

  test("treats an empty known executable name as unknown-command", () => {
    const result = analyze('"$EMPTY"', [], fromInitialEnvironment({ EMPTY: "" }));

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
  });
});

function analyze(
  source: string,
  handlers: readonly PolicyObserver[],
  environment = fromInitialEnvironment(),
) {
  const program = parseBashProgram(source);
  expect(program.kind).toBe("program");
  if (program.kind !== "program") throw new Error(program.reason);

  const registry = createCommandRegistry(handlers);
  const initial = walkProgram(program, {
    environment,
    dispatchCommand: (request) => dispatchCommand(request, registry),
  });
  return { completed: runSteps(initial) };
}

function recordingHandler(
  name: string,
  invocations: InvocationCursor[],
  onInvocation?: (cursor: InvocationCursor) => void,
): PolicyObserver {
  return {
    name,
    observe(cursor) {
      invocations.push(cursor);
      onInvocation?.(cursor);
      return observePolicy(safe());
    },
  };
}

function denyHandler(name: string): PolicyObserver {
  return {
    name,
    observe() {
      return observePolicy({ kind: "deny", span: { start: 0, end: 0 } });
    },
  };
}

function directWrapperDispatch(executable: string, argv: readonly (string | undefined)[]) {
  const environment = fromInitialEnvironment();
  const scheduled: string[] = [];
  const request: BashDispatchRequest = {
    command: {
      executable: { kind: "known", value: executable },
      argv: argv.map((value) => value === undefined
        ? { kind: "unknown", reason: { kind: "property", span: { start: 0, end: 0 } } }
        : { kind: "known", value }),
      redirects: [],
      environment,
      assignmentPatch: { environment, writes: new Set() },
    },
    span: { start: 0, end: 0 },
    environment,
    functionDepth: 0,
    nestedScriptDepth: 0,
    provenance: { route: ["direct"] },
    continueWith: (source) => {
      scheduled.push(source);
      return {
        outcome: safe(),
        continuations: [{
          source,
          environment,
          functionDepth: 0,
          nestedScriptDepth: 1,
          inPipeline: false,
          isolate: true,
          environmentExplicit: false,
          provenance: { route: ["direct"] },
        }],
      };
    },
  };
  return { result: dispatchCommand(request), scheduled };
}

function dispatchOutcome(result: BashDispatchResult) {
  return "kind" in result ? result : result.outcome;
}

function renderInvocation(cursor: InvocationCursor): string[] {
  const executable = cursor.invocation.executable;
  if (executable?.kind !== "known") throw new Error("expected known invocation executable");
  return [executable.value, ...cursor.invocation.argv.map((argument) => {
    if (argument.kind !== "known") throw new Error("expected known invocation argument");
    return argument.value;
  })];
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function shuffle<T>(values: readonly T[], random: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index--) {
    const other = random() % (index + 1);
    [result[index], result[other]] = [result[other]!, result[index]!];
  }
  return result;
}
