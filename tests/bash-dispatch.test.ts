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
  preflightCommand,
  type InvocationCursor,
  type PolicyObserver,
} from "../src/bash/dispatch.ts";
import { fromInitialEnvironment, fromVerifiedInitialEnvironment, unknown } from "../src/bash/environment.ts";
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
    "bash -co pipefail 'denied-command'",
    "bash -c \"denied-command\"",
    "bash -Ec 'denied-command'",
    "bash -Tc 'denied-command'",
    "bash --debug -c 'denied-command'",
    "bash --pretty-print -c 'denied-command'",
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

  test("property: best-effort zsh short-flag clusters preserve nested denials", () => {
    const random = lcg(0x18c4_a72f);
    for (let iteration = 0; iteration < 64; iteration++) {
      const flags = shuffle(["d", "f", "E", "T", "x"], random).join("");
      const source = `zsh -${flags}c 'denied-command'`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("property: best-effort zsh named options preserve nested denials", () => {
    for (const option of ["--no-rcs", "--no-global-rcs", "--no_rcs", "--GLOBAL_RCS", "+-RCS", "+-no-RCS", "--rcs", "--global-rcs", "--interactive", "--login"]) {
      const source = `zsh ${option} -c 'denied-command'`;
      expect(analyze(source, [denyHandler("denied-command")]).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test.each([
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
  ])("blocks fish command source pending dedicated parser support: %s", (source) => {
    expect(analyze(source, [denyHandler("denied-command")]).completed.verdict).toMatchObject({ kind: "deny" });
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

  test("recognized structural parse failures schedule a redacted opaque execution", () => {
    for (const [executable, argv] of [
      ["exec", ["--unknown", "opaque-canary"]],
      ["bash", ["--unknown", "opaque-canary"]],
      ["timeout", ["--unknown", "1s", "opaque-canary"]],
    ] as const) {
      const result = directWrapperDispatch(executable, argv);
      expect(result.targets, executable).toContain("opaque");
      expect(dispatchOutcome(result.result), executable).toMatchObject({ kind: "indeterminate" });
      expect(JSON.stringify(result.result), executable).not.toContain("opaque-canary");
    }
  });

  test("preserves known shell command options when their required value is dynamic", () => {
    const bash = directWrapperDispatch("bash", ["-c", undefined], fromVerifiedInitialEnvironment());
    expect(bash.targets).toEqual(["opaque"]);
    expect(bash.effects).toEqual(["spawn-and-wait"]);

    const zsh = directWrapperDispatch("zsh", ["-c", undefined], fromVerifiedInitialEnvironment());
    expect(zsh.targets).toEqual(["opaque", "opaque"]);
    expect(zsh.effects).toEqual(["spawn-and-wait", "spawn-and-wait"]);

    const fish = directWrapperDispatch("fish", ["-c", undefined], fromVerifiedInitialEnvironment());
    expect(dispatchOutcome(fish.result)).toMatchObject({ kind: "deny", policy: { name: "unsupported-shell-source" } });

    const missing = directWrapperDispatch("bash", ["-c"], fromVerifiedInitialEnvironment());
    expect(missing.targets).toEqual(["opaque"]);
    expect(dispatchOutcome(missing.result)).toMatchObject({ kind: "indeterminate" });
  });

  test("continues through dynamic non-command option values to inspect static command source", () => {
    const environment = fromInitialEnvironment({ OPTION: unknown({ kind: "ambient" }) });
    expect(analyze('bash -o "$OPTION" -c denied-command', [denyHandler("denied-command")], environment).completed.verdict)
      .toMatchObject({ kind: "deny" });
    expect(analyze('zsh -o "$OPTION" -c denied-command', [denyHandler("denied-command")], environment).completed.verdict)
      .toMatchObject({ kind: "deny" });
    expect(analyze('fish -d "$OPTION" -c true', [], environment).completed.verdict)
      .toMatchObject({ kind: "deny" });
  });

  test("walks a statically known sh -c script only through a source child", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("sh -c 'gh pr create --repo github.com/acme/widgets'", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations.map(renderInvocation)).toEqual([[
      "gh", "pr", "create", "--repo", "github.com/acme/widgets",
    ]]);
  });

  test("schedules direct source builtins as opaque current-scope execution", () => {
    for (const executable of ["source", "."] as const) {
      const direct = directWrapperDispatch(executable, ["setup.sh"]);
      expect(direct.targets, executable).toEqual(["opaque"]);
      expect(direct.effects, executable).toEqual(["none"]);

      const invocations: InvocationCursor[] = [];
      const result = analyze(`X=known; ${executable} setup.sh; run "$X"`, [recordingHandler("run", invocations)]);
      expect(result.completed.outcome, executable).toMatchObject({ kind: "failure", reason: "analysis-failure" });
      expect(invocations[0]?.invocation.argv[0], executable).toMatchObject({ kind: "unknown" });
    }
  });

  test("preserves possible prior functions across opaque source execution", () => {
    for (const executable of ["source", "."] as const) {
      const result = analyze(`f(){ denied-command; }; ${executable} setup.sh; f`, [denyHandler("denied-command")]);
      expect(result.completed.outcome, executable).toMatchObject({ kind: "deny" });
    }
  });

  test("walks malformed nested script prefixes for every source target route", () => {
    for (const source of [
      "eval 'denied-command; if'",
      "bash -c 'denied-command; if'",
      "watch 'denied-command; if'",
    ]) {
      expect(analyze(source, [denyHandler("denied-command")]).completed.outcome, source).toMatchObject({ kind: "deny" });
    }
  });

  test("reports malformed-only nested scripts as profile-independent failure", () => {
    for (const source of ["eval 'if'", "bash -c 'if'", "watch 'if'"]) {
      expect(analyze(source, []).completed.outcome, source).toMatchObject({ kind: "failure", reason: "analysis-failure" });
    }
  });

  test("schedules explicit and inherited shell startup as opaque execution", () => {
    const explicit = directWrapperDispatch("bash", ["--rcfile", "setup.sh", "-ic", "true"]);
    expect(explicit.targets).toEqual(["source", "opaque"]);
    expect(explicit.effects).toEqual(["spawn-and-wait", "spawn-and-wait"]);

    for (const [source, environment] of [
      ["bash -c true", fromInitialEnvironment({ BASH_ENV: "setup.sh" })],
      ["sh -c true", fromInitialEnvironment({ ENV: "setup.sh" })],
      ["zsh -c true", fromInitialEnvironment({ ZDOTDIR: "/tmp/zsh" })],
    ] as const) {
      expect(analyze(source, [], environment).completed.outcome, source).toMatchObject({ kind: "failure", reason: "analysis-failure" });
    }
  });

  test("derives Bash and zsh startup from invocation mode with a verified empty environment", () => {
    const environment = fromVerifiedInitialEnvironment();
    for (const [executable, argv] of [
      ["bash", ["-ic", "true"]],
      ["bash", ["-lc", "true"]],
      ["zsh", ["-c", "true"]],
    ] as const) {
      const direct = directWrapperDispatch(executable, argv, environment);
      expect(direct.targets, `${executable} ${argv.join(" ")}`).toEqual(["source", "opaque"]);
      expect(direct.effects, `${executable} ${argv.join(" ")}`).toEqual(["spawn-and-wait", "spawn-and-wait"]);
    }

    expect(analyze("zsh -fc true", [], environment).completed.outcome).toMatchObject({
      kind: "failure",
      reason: "analysis-failure",
    });
  });

  test("suppresses only the reviewed Bash startup mode", () => {
    const environment = fromVerifiedInitialEnvironment();
    for (const argv of [
      ["--norc", "-ic", "true"],
      ["--noprofile", "-lc", "true"],
    ]) {
      expect(directWrapperDispatch("bash", argv, environment).targets, argv.join(" ")).toEqual(["source"]);
    }
    expect(directWrapperDispatch("bash", ["--norc", "-ic", "true"]).targets).toEqual(["source"]);
    for (const argv of [
      ["--noprofile", "-ic", "true"],
      ["--norc", "-lc", "true"],
      ["--norc", "--rcfile", "setup.sh", "-ic", "true"],
    ]) {
      expect(directWrapperDispatch("bash", argv, environment).targets, argv.join(" ")).toEqual(["source", "opaque"]);
    }
  });

  test("property: Bash startup suppression survives reviewed option clusters and orderings", () => {
    const environment = fromVerifiedInitialEnvironment();
    const clusters = ["-ic", "-xic", "-ixc", "-lc", "-xlc", "-lxc"];
    for (let iteration = 0; iteration < 64; iteration++) {
      const cluster = clusters[iteration % clusters.length]!;
      const interactive = cluster.includes("i");
      const suppressor = interactive ? "--norc" : "--noprofile";
      const irrelevant = interactive ? "--noprofile" : "--norc";
      const before = iteration % 2 === 0 ? [suppressor, "-T"] : ["-T", suppressor];
      expect(directWrapperDispatch("bash", [...before, cluster, "true"], environment).targets, String(iteration))
        .toEqual(["source"]);
      expect(directWrapperDispatch("bash", [irrelevant, cluster, "true"], environment).targets, String(iteration))
        .toEqual(["source", "opaque"]);
    }
  });

  test("classifies wrapper child targets and process effects", () => {
    for (const [executable, argv, target, effect] of [
      ["command", ["cat"], "invocation", "none"],
      ["exec", ["cat"], "invocation", "exec-replace"],
      ["env", ["cat"], "invocation", "exec-replace"],
      ["time", ["cat"], "invocation", "spawn-and-wait"],
      ["timeout", ["1s", "cat"], "invocation", "spawn-and-wait"],
      ["strace", ["cat"], "invocation", "spawn-and-wait"],
      ["watch", ["--exec", "cat"], "invocation", "spawn-repeated"],
      ["watch", ["cat"], "source", "spawn-repeated"],
      ["xargs", ["cat"], "invocation", "spawn-repeated"],
      ["find", [".", "-exec", "cat", ";"], "invocation", "spawn-repeated"],
      ["setsid", ["--fork", "cat"], "invocation", "spawn-async"],
      ["setsid", ["--fork", "--wait", "cat"], "invocation", "spawn-and-wait"],
      ["sudo", ["-b", "cat"], "invocation", "spawn-async"],
      ["sudo", ["cat"], "invocation", "unknown"],
    ] as const) {
      const result = directWrapperDispatch(executable, argv);
      expect(result.targets, executable).toEqual([target]);
      expect(result.effects, executable).toEqual([effect]);
    }
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

  test("keeps unresolved find actions opaque beside known siblings", () => {
    for (const argv of [
      [".", "-exec", "known-command", ";", "-exec", undefined, ";"],
      [".", "-exec", undefined, ";", "-exec", "known-command", ";"],
      [".", "-exec", "known-command", ";", "-exec", "unterminated"],
    ] as const) {
      const direct = directWrapperDispatch("find", argv);
      expect(direct.targets, JSON.stringify(argv)).toContain("invocation");
      expect(direct.targets, JSON.stringify(argv)).toContain("opaque");
      expect(direct.effects.every((effect) => effect === "spawn-repeated"), JSON.stringify(argv)).toBeTrue();
    }

    const runtime = analyze("find . -exec allowed-command \\; -exec $UNKNOWN \\;", [], {
      UNKNOWN: unknown({ kind: "ambient" }),
    });
    expect(runtime.completed.outcome).toMatchObject({ kind: "failure", reason: "analysis-failure" });
  });

  test("property: every unresolved find action remains opaque under sibling ordering", () => {
    for (let index = 0; index < 64; index++) {
      const knownAction = ["-exec", `known-${index}`, ";"] as const;
      const unknownAction = ["-execdir", undefined, ";"] as const;
      const actions = index % 2 === 0 ? [...knownAction, ...unknownAction] : [...unknownAction, ...knownAction];
      const direct = directWrapperDispatch("find", [".", ...actions]);
      expect(direct.targets, String(index)).toContain("invocation");
      expect(direct.targets, String(index)).toContain("opaque");
    }
  });

  test("uses GNU find primary arity before recognizing execution actions", () => {
    const operand = directWrapperDispatch("find", [".", "-name", "-exec", "denied-command", ";"]);
    expect(operand.targets).not.toContain("invocation");

    const dynamicOperand = directWrapperDispatch("find", [".", "-name", undefined, "-exec", "known-command", ";"]);
    expect(dynamicOperand.targets).toEqual(["invocation"]);

    const dynamicPrimary = directWrapperDispatch("find", [".", undefined, "-exec", "known-command", ";"]);
    expect(dynamicPrimary.targets).toContain("opaque");
    expect(dynamicPrimary.targets).toContain("invocation");
  });

  test("property: reviewed fixed-arity find operands are never reinterpreted as actions", () => {
    const unary = [
      "-amin", "-anewer", "-atime", "-cmin", "-cnewer", "-ctime", "-fls", "-fprint", "-fprint0",
      "-fstype", "-gid", "-group", "-ilname", "-iname", "-inum", "-ipath", "-iregex", "-links",
      "-lname", "-maxdepth", "-mindepth", "-mmin", "-mtime", "-name", "-newer", "-path", "-perm",
      "-printf", "-regextype", "-samefile", "-size", "-type", "-uid", "-used", "-user", "-wholename", "-xtype",
    ];
    for (const primary of unary) {
      const result = directWrapperDispatch("find", [".", primary, "-exec", "canary", ";"]);
      expect(result.targets, primary).not.toContain("invocation");
    }
    expect(directWrapperDispatch("find", [".", "-fprintf", "-exec", "format", "canary", ";"]).targets)
      .not.toContain("invocation");
  });

  test("keeps unresolved find primary and action positions opaque beside concrete siblings", () => {
    for (const argv of [
      [".", undefined, "-exec", "known-command", ";"],
      [".", "-exec", undefined, ";", "-exec", "known-command", ";"],
      [".", "-exec", "known-command", ";", undefined],
    ] as const) {
      const result = directWrapperDispatch("find", argv);
      expect(result.targets, JSON.stringify(argv)).toContain("opaque");
      expect(result.targets, JSON.stringify(argv)).toContain("invocation");
    }
  });

  test("inspects actions exposed by a possible dynamic find terminator", () => {
    const result = directWrapperDispatch("find", [
      ".", "-exec", "unknown-command", undefined, "-exec", "known-command", ";",
    ]);
    expect(result.targets).toContain("opaque");
    expect(result.targets).toContain("invocation");
  });

  test("recognizes only the GNU batched action terminator immediately following an exact placeholder", () => {
    expect(directWrapperDispatch("find", [".", "-exec", "known-command", "{}", "+"]).targets).toContain("invocation");
    expect(directWrapperDispatch("find", [".", "-exec", "known-command", "+"]).targets).toContain("opaque");
    expect(directWrapperDispatch("find", [".", "-exec", "known-command", "{}", "{}", "+"]).targets).toContain("opaque");
    expect(directWrapperDispatch("find", [".", "-ok", "known-command", "{}", "+"]).targets).toContain("opaque");
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
        const expected = executable === "sh" && boundary === 1 ? "safe" : "indeterminate";
        expect(dispatchOutcome(result.result), `${executable}:${boundary}`).toMatchObject({ kind: expected });
        if (expected === "safe") expect(result.targets).toContain("opaque");
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
    preflightCommand: (request) => preflightCommand(request, registry),
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

function directWrapperDispatch(
  executable: string,
  argv: readonly (string | undefined)[],
  environment = fromInitialEnvironment(),
) {
  const scheduled: string[] = [];
  const targets: Array<"source" | "invocation" | "opaque"> = [];
  const effects: string[] = [];
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
    inPipeline: false,
    processEffect: "none",
    continueWithSource: (source, _environment, options) => {
      scheduled.push(source);
      targets.push("source");
      effects.push(options?.processEffect ?? "spawn-and-wait");
      return {
        outcome: safe(),
        children: [{
          target: { kind: "source", source, dialect: "bash", sourceDerivedFromBinding: false },
          processEffect: "spawn-and-wait",
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
    continueWithInvocation: (words, _environment, options) => {
      scheduled.push(words.map((word) => word.kind === "known" ? word.value : "<unknown>").join(" "));
      targets.push("invocation");
      effects.push(options?.processEffect ?? "exec-replace");
      return {
        outcome: safe(),
        children: [],
      };
    },
    continueWithOpaque: (_reason, _environment, options) => {
      targets.push("opaque");
      effects.push(options?.processEffect ?? "unknown");
      return { outcome: safe(), children: [] };
    },
  };
  return { result: dispatchCommand(request), scheduled, targets, effects };
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
