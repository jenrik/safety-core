import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeBashAuthorization,
  evaluateBashGuards,
  initBashParser,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-hard-block-policies-"));

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

describe("walker-backed hard-block compatibility policies", () => {
  test("detects readers resolved through assignments and transparent wrappers", () => {
    expectGuardBlock("READER=cat; strace $READER credentials.json", "secret-read");
    expectGuardBlock("cat README.md; env -i cat credentials.json", "secret-read");
    expectGuardBlock("xargs cat credentials.json </dev/null", "secret-read");
    expectGuardBlock("find . -maxdepth 0 -exec cat credentials.json {} \\;", "secret-read");
    expectGuardBlock("eval -- 'cat credentials.json'", "secret-read");
    expectGuardBlock("builtin eval 'cat credentials.json'", "secret-read");
    expectGuardBlock("builtin source credentials.json", "secret-read");
    expectGuardBlock("builtin . credentials.json", "secret-read");
    expectGuardBlock("builtin command cat credentials.json", "secret-read");
    expectGuardBlock("builtin exec cat credentials.json", "secret-read");
    expectGuardBlock("fish -C 'cat credentials.json' -c true", "secret-read");
    expectGuardBlock("fish -d parser -c 'cat credentials.json'", "secret-read");
    expectGuardBlock("fish --interactive -c 'cat credentials.json'", "secret-read");
    expectGuardBlock("zsh --no-rcs -c 'cat credentials.json'", "secret-read");
    expectGuardBlock("zsh --no_rcs -c 'cat credentials.json'", "secret-read");
    expectGuardBlock("fish --init-cmd 'cat credentials.json' -c true", "secret-read");
    expectGuardBlock("sudo cat credentials.json", "secret-read");
    expectGuardBlock("sudo -e credentials.json", "secret-read");
    expectGuardBlock("sudo --edit credentials.json", "secret-read");
    expectGuardBlock("sudoedit credentials.json", "secret-read");
    expectGuardBlock("find -files0-from credentials.json -print", "secret-read");
    expectGuardBlock("bash --noprofile --rcfile credentials.json -ic true", "secret-read");
    expectGuardBlock("bash --init-file=credentials.json -ic true", "secret-read");
    expectGuardBlock("BASH_ENV=credentials.json bash -c true", "secret-read");
  });

  test("property: shell script-file modes block protected operands", () => {
    for (const shell of ["sh", "bash", "dash", "fish", "ksh", "zsh"]) {
      expectGuardBlock(`${shell} credentials.json`, "secret-read");
      expectGuardBlock(`${shell} -- credentials.json`, "secret-read");
    }
  });

  test("property: xargs arg-file aliases block protected inputs before child analysis", () => {
    for (const source of [
      "xargs -a credentials.json echo",
      "xargs -acredentials.json echo",
      "xargs --arg-file credentials.json echo",
      "xargs --arg-file=credentials.json echo",
      "xargs -racredentials.json echo",
      "xargs -ra credentials.json echo",
      "xargs -0acredentials.json echo",
    ]) expectGuardBlock(source, "secret-read");
  });

  test("retains short-circuit path correlations needed for hard blocks", () => {
    expectGuardBlock('condition && FILE=credentials.json; cat "$FILE"', "secret-read");
    expectGuardBlock("condition || # keep the right operand\ncat credentials.json", "secret-read");
    expectGuardBlock(
      'X=credentials.json; Y=README.md; condition && X=README.md || Y=$X; cat "$Y"',
      "secret-read",
    );
  });

  test("applies env environment operands to its child while keeping the wrapper prompt-gated", () => {
    const blocked = "https://api.github.com/repos/example/project/issues";

    expect(analyzeBashAuthorization({ source: "env -i -- sh -c 'curl \"$URL\"'", initialEnvironment: { kind: "verified", values: { URL: blocked } } }).verdict)
      .toEqual({ kind: "neutral" });
    expect(analyzeBashAuthorization({ source: `env -u URL URL=${blocked} sh -c 'curl \"$URL\"'` }).verdict)
      .toMatchObject({ kind: "deny" });
  });

  test("denies path-qualified reader commands", () => {
    expectGuardBlock("/bin/cat credentials.json", "secret-read");
  });

  test("denies secret input redirects for arbitrary commands and redirect-only commands", () => {
    for (const command of [
      "wc < credentials.json", "bash < credentials.json", "< credentials.json",
      "(cat) < credentials.json", "{ cat; } < credentials.json",
    ]) {
      expectGuardBlock(command, "secret-read", "bash redirect from 'credentials.json'");
    }
  });

  test.each([
    '"$UNKNOWN" < credentials.json',
    "f(){ true; }; f < credentials.json",
    "export VALUE < credentials.json",
  ])("denies a secret input redirect before the shortcut in %s", (command) => {
    expectGuardBlock(command, "secret-read", "bash redirect from 'credentials.json'");
  });

  test("denies a secret input redirect before the readonly-assignment shortcut", () => {
    expectGuardBlock("readonly VALUE=old; VALUE=next cat < credentials.json", "secret-read", "bash redirect from 'credentials.json'");
  });

  test("detects direct GitHub HTTP invocations", () => {
    expectGuardBlock("curl https://api.github.com/repos/o/r/issues", "github-http", "Use the native gh command");
    expectGuardBlock("curl https://example.test; strace curl https://api.github.com/repos/o/r/issues", "github-http", "Use the native gh command");
    expectGuardBlock("(curl https://api.github.com/repos/o/r/issues) > trace.log", "github-http", "Use the native gh command");
  });

  test("recognizes ANSI-C executable quoting and shell long options before --command", () => {
    expectGuardBlock("$'cu'rl https://api.github.com/repos/o/r/issues", "github-http", "Use the native gh command");
    expectGuardBlock("bash --noprofile --command 'curl https://api.github.com/repos/o/r/issues'", "github-http", "Use the native gh command");
    expectGuardBlock("bash -c 'curl \"$2\"' shell-name ignored https://api.github.com/repos/o/r/issues", "github-http", "Use the native gh command");
  });

  test("does not expose a resolved URL or query in GitHub policy evidence", () => {
    const resolved = "https://api.github.com/repos/o/r/issues?opaque-query-marker";
    const analysis = analyzeBashAuthorization({ source: "curl \"$URL\"", initialEnvironment: { kind: "verified", values: { URL: resolved } } });
    const reason = analysis.policies.find((policy) => policy.name === "github-http")?.reason ?? "";

    expect(analysis.policies.length).toBe(1);
    expect(reason).not.toContain(resolved);
    expect(JSON.stringify(analysis)).not.toContain(resolved);
  });

  test("does not expose binding-derived GitHub query data after a transparent wrapper", () => {
    const resolved = "https://api.github.com/repos/o/r/issues?opaque-query-marker";
    const analysis = analyzeBashAuthorization({
      source: "strace -f curl \"$URL\"",
      initialEnvironment: { kind: "verified", values: { URL: resolved } },
    });
    const reason = analysis.policies.find((policy) => policy.name === "github-http")?.reason ?? "";

    expect(analysis.policies.length).toBe(1);
    expect(reason).not.toContain(resolved);
    expect(JSON.stringify(analysis)).not.toContain(resolved);
  });

  test("does not expose a binding-derived GitHub URL after literal eval reparsing", () => {
    const resolved = "https://api.github.com/repos/o/r/issues";
    const analysis = analyzeBashAuthorization({
      source: "eval curl \"$URL\"",
      initialEnvironment: { kind: "verified", values: { URL: resolved } },
    });
    const reason = analysis.policies.find((policy) => policy.name === "github-http")?.reason ?? "";

    expect(analysis.policies.length).toBe(1);
    expect(reason).not.toContain(resolved);
    expect(JSON.stringify(analysis)).not.toContain(resolved);
  });

  test("recurses into known literal eval payloads while keeping unknown eval payloads neutral", () => {
    expectGuardBlock("eval 'cat credentials.json'", "secret-read");
    expect(analyzeBashAuthorization({ source: "eval \"$UNKNOWN\"" }).verdict).toEqual({ kind: "neutral" });
  });

  test("preserves URL-specific steering for path-qualified HTTP commands", () => {
    const url = "https://api.github.com/repos/o/r/issues";
    expectGuardBlock(`/usr/bin/curl ${url}`, "github-http", "Use the native gh command");
  });

  test("detects kubectl Secret reads resolved through assignments and wrappers", () => {
    expectKubectlSecretReview("TOOL=kubectl; strace $TOOL get secret app");
    expectKubectlSecretReview("TOOL=kubectl; strace $TOOL --namespace default get secret app");
  });

  test("denies path-qualified kubectl commands and preserves no-subcommand compatibility", () => {
    expectGuardBlock("/usr/bin/kubectl view-secret app", "kubectl", "kubectl view-secret is blocked");
    expect(evaluateBashGuards({ source: "kubectl" })).toMatchObject({ kind: "pass" });
  });

  test("allows only a complete set of known-safe hard-block invocations", () => {
    expect(analyzeBashAuthorization({ source: "cat README.md; curl https://example.test; kubectl get pods" }).verdict)
      .toEqual({ kind: "allow" });
  });

  test("keeps ambient variable expansion neutral instead of reading process environment", () => {
    expect(analyzeBashAuthorization({ source: "$READER credentials.json" }).verdict).toEqual({ kind: "neutral" });
  });

  test("property: a later hard-block denial dominates preceding indeterminate evidence", () => {
    const random = lcg(0x7337c0de);
    const blocked = [
      "cat credentials.json",
      "curl https://api.github.com/repos/o/r/issues",
      "kubectl view-secret app",
    ];
    const wrappers = [
      (command: string) => command,
      (command: string) => `strace -f ${command}`,
      (command: string) => `env -i ${command}`,
      (command: string) => `sh -c '${command}'`,
    ];

    for (let iteration = 0; iteration < 96; iteration++) {
      const command = blocked[random() % blocked.length]!;
      const wrap = wrappers[random() % wrappers.length]!;
      const safePrefix = ["cat README.md", "curl https://example.test", "kubectl get pods"][random() % 3]!;
      expect(analyzeBashAuthorization({ source: `${safePrefix}; unknown-command; ${wrap(command)}` }).verdict.kind)
        .toBe("deny");
    }
  });

  test("property: compound forms never bypass a secret input redirect", () => {
    for (const command of ["cat", "wc", "bash"]) {
      for (const source of [`(${command}) < credentials.json`, `{ ${command}; } < credentials.json`]) {
        expectGuardBlock(source, "secret-read", "bash redirect from 'credentials.json'");
      }
    }
  });

  test("property: flattened short-circuit chains preserve a reachable secret assignment", () => {
    for (let length = 1; length <= 32; length++) {
      const conditions = Array.from({ length }, (_, index) => `condition-${index}`);
      const source = `${conditions.join(" && ")} && FILE=credentials.json; cat "$FILE"`;

      expectGuardBlock(source, "secret-read");
    }
  });
});

function expectGuardBlock(source: string, policy: "secret-read" | "github-http" | "kubectl", reason?: string): void {
  const result = evaluateBashGuards({ source });
  expect(result, source).toMatchObject({ kind: "block", policy: { name: policy, decision: "deny" } });
  if (reason !== undefined) expect(result.reason, source).toContain(reason);
}

function expectKubectlSecretReview(source: string): void {
  expect(evaluateBashGuards({ source }), source).toMatchObject({
    kind: "pass",
    policies: [expect.objectContaining({
      name: "kubectl",
      decision: "defer",
      kubectl: expect.objectContaining({ secretReview: true }),
    })],
  });
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
