import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeBashAuthorization,
  analyzeKubectl,
  buildGithubSuggestion,
  checkBashForGithub,
  checkBashForKubectlSecret,
  initBashParser,
  parseBashForSecretRead,
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
    expect(parseBashForSecretRead("READER=cat; strace $READER credentials.json")).toContain("cat");
    expect(parseBashForSecretRead("cat README.md; env -i cat credentials.json")).toContain("cat");
  });

  test("retains short-circuit path correlations needed for hard blocks", () => {
    expect(parseBashForSecretRead('condition && FILE=credentials.json; cat "$FILE"')).toContain("cat");
    expect(parseBashForSecretRead("condition || # keep the right operand\ncat credentials.json")).toContain("cat");
    expect(parseBashForSecretRead(
      'X=credentials.json; Y=README.md; condition && X=README.md || Y=$X; cat "$Y"',
    )).toContain("cat");
  });

  test("applies env environment operands to its child command", () => {
    const blocked = "https://api.github.com/repos/example/project/issues";

    expect(analyzeBashAuthorization({ source: "env -i -- sh -c 'curl \"$URL\"'", initialEnvironment: { kind: "verified", values: { URL: blocked } } }).verdict)
      .toEqual({ kind: "allow" });
    expect(analyzeBashAuthorization({ source: `env -u URL URL=${blocked} sh -c 'curl \"$URL\"'` }).verdict)
      .toMatchObject({ kind: "deny" });
  });

  test("denies path-qualified reader commands", () => {
    expect(parseBashForSecretRead("/bin/cat credentials.json")).toContain("cat");
  });

  test("denies secret input redirects for arbitrary commands and redirect-only commands", () => {
    for (const command of ["wc < credentials.json", "bash < credentials.json", "< credentials.json"]) {
      expect(parseBashForSecretRead(command), command).toBe("bash redirect from 'credentials.json'");
    }
  });

  test.each([
    '"$UNKNOWN" < credentials.json',
    "f(){ true; }; f < credentials.json",
    "export VALUE < credentials.json",
  ])("denies a secret input redirect before the shortcut in %s", (command) => {
    expect(parseBashForSecretRead(command)).toBe("bash redirect from 'credentials.json'");
  });

  test("denies a secret input redirect before the readonly-assignment shortcut", () => {
    expect(parseBashForSecretRead("readonly VALUE=old; VALUE=next cat < credentials.json"))
      .toBe("bash redirect from 'credentials.json'");
  });

  test("detects direct GitHub HTTP invocations", () => {
    expect(checkBashForGithub("curl https://api.github.com/repos/o/r/issues")).toContain("Use the native gh command");
    expect(checkBashForGithub("curl https://example.test; strace curl https://api.github.com/repos/o/r/issues"))
      .toContain("Use the native gh command");
  });

  test("recognizes ANSI-C executable quoting and shell long options before --command", () => {
    expect(checkBashForGithub("$'cu'rl https://api.github.com/repos/o/r/issues")).toContain("Use the native gh command");
    expect(checkBashForGithub("bash --noprofile --command 'curl https://api.github.com/repos/o/r/issues'"))
      .toContain("Use the native gh command");
    expect(checkBashForGithub("bash -c 'curl \"$2\"' shell-name ignored https://api.github.com/repos/o/r/issues"))
      .toContain("Use the native gh command");
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
    expect(parseBashForSecretRead("eval 'cat credentials.json'")).toContain("cat");
    expect(analyzeBashAuthorization({ source: "eval \"$UNKNOWN\"" }).verdict).toEqual({ kind: "neutral" });
  });

  test("preserves URL-specific steering for path-qualified HTTP commands", () => {
    const url = "https://api.github.com/repos/o/r/issues";
    expect(checkBashForGithub(`/usr/bin/curl ${url}`)).toBe(buildGithubSuggestion(url));
  });

  test("detects kubectl Secret reads resolved through assignments and wrappers", () => {
    expect(checkBashForKubectlSecret("TOOL=kubectl; strace $TOOL get secret app")).toContain("kubectl get Secret");
    expect(checkBashForKubectlSecret("TOOL=kubectl; strace $TOOL --namespace default get secret app")).toContain("kubectl get Secret");
  });

  test("denies path-qualified kubectl commands and preserves no-subcommand compatibility", () => {
    expect(checkBashForKubectlSecret("/usr/bin/kubectl view-secret app")).toContain("kubectl view-secret is blocked");
    expect(analyzeKubectl("kubectl")).toEqual({ kind: "ignore" });
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

  test("property: flattened short-circuit chains preserve a reachable secret assignment", () => {
    for (let length = 1; length <= 32; length++) {
      const conditions = Array.from({ length }, (_, index) => `condition-${index}`);
      const source = `${conditions.join(" && ")} && FILE=credentials.json; cat "$FILE"`;

      expect(parseBashForSecretRead(source), source).toContain("cat");
    }
  });
});

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
