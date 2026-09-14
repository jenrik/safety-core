import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  checkBashForGithub,
  checkBashForKubectlSecret,
  evaluateBashGuards,
  initBashParser,
  parseBashForSecretRead,
  setJudgeProvider,
  type BashGuardEvaluation,
  type BashGuardOptions,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-opencode-bash-guards-"));
let openCodeBashGuardBlockReason: typeof import("../adapters/opencode.ts")["openCodeBashGuardBlockReason"];
let createOpenCodePlugin: typeof import("../adapters/opencode.ts")["createOpenCodePlugin"];

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
  const adapter = await import("../adapters/opencode.ts");
  openCodeBashGuardBlockReason = adapter.openCodeBashGuardBlockReason;
  createOpenCodePlugin = adapter.createOpenCodePlugin;
});

afterAll(() => {
  setJudgeProvider(null);
  rmSync(wasmDir, { force: true, recursive: true });
});

describe("OpenCode single-pass Bash guards", () => {
  test("maps baseline policies to their existing OpenCode messages", () => {
    const secret = "cat credentials.json";
    const github = "curl https://api.github.com/user";
    const kubectl = "kubectl view-secret application";
    expect(openCodeBashGuardBlockReason(secret, context()))
      .toBe(`Blocked by OpenCode safety policy: ${parseBashForSecretRead(secret, context())}`);
    expect(openCodeBashGuardBlockReason(github, context()))
      .toBe(checkBashForGithub(github, context()));
    expect(openCodeBashGuardBlockReason(kubectl, context()))
      .toBe(`Blocked by OpenCode safety policy: ${checkBashForKubectlSecret(kubectl, context())}`);
    expect(openCodeBashGuardBlockReason("kubectl get Secret application", context())).toBeNull();
    expect(openCodeBashGuardBlockReason("unknown-command", context())).toBeNull();
  });

  test("invokes the core guard evaluator exactly once through the real callback", async () => {
    let calls = 0;
    const evaluate = (options: BashGuardOptions): BashGuardEvaluation => {
      calls++;
      expect(options).toMatchObject({
        source: "cat README.md",
        initialEnvironment: { kind: "unavailable" },
      });
      return evaluateBashGuards(options);
    };

    const plugin = await createOpenCodePlugin({ evaluateBashGuards: evaluate });
    const before = plugin["tool.execute.before"] as Function;
    await expect(before(bashInput(), bashOutput("cat README.md"))).resolves.toBeUndefined();
    expect(calls).toBe(1);
  });

  test("the real before-execution callback preserves blocks and kubectl judge review", async () => {
    const plugin = await createOpenCodePlugin();
    const before = plugin["tool.execute.before"] as Function;

    await expect(before(bashInput(), bashOutput("cat credentials.json")))
      .rejects.toThrow("Blocked by OpenCode safety policy: bash `cat`");
    await expect(before(bashInput(), bashOutput("curl https://api.github.com/user")))
      .rejects.toThrow("Blocked: https://api.github.com/user");
    await expect(before(bashInput(), bashOutput("kubectl view-secret application")))
      .rejects.toThrow("Blocked by OpenCode safety policy: kubectl view-secret is blocked");

    let judgeCalls = 0;
    setJudgeProvider(async () => {
      judgeCalls++;
      return { safe: true, reasoning: "metadata-only Secret review" };
    });
    await expect(before(bashInput(), bashOutput("kubectl get Secret application"))).resolves.toBeUndefined();
    expect(judgeCalls).toBe(1);
  });
});

function context() {
  return Object.freeze({ initialEnvironment: { kind: "unavailable" as const } });
}

function bashInput() {
  return { tool: "bash" };
}

function bashOutput(command: string) {
  return { args: { command } };
}
