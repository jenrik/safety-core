import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-opencode-read-only-cli-"));
const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-profile-"));
const originalConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
  process.env.SAFETY_CORE_CONFIG_HOME = configHome;
  mkdirSync(join(configHome, "safety-core"), { recursive: true });
});

afterAll(() => {
  if (originalConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
  else process.env.SAFETY_CORE_CONFIG_HOME = originalConfigHome;
  rmSync(wasmDir, { force: true, recursive: true });
  rmSync(configHome, { force: true, recursive: true });
});

async function permissionStatus(command: string): Promise<string> {
  const plugin = await (await import("../adapters/opencode.ts")).default();
  const output = { status: "ask" };
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: command }, output);
  return output.status;
}

describe("OpenCode read-only CLI profiles", () => {
  test("allows gh and Helm reads, hands gh api to its dedicated profile, and preserves compound prompts", async () => {
    writeFileSync(
      join(configHome, "safety-core", "profiles.json"),
      JSON.stringify({ ghReadOnly: true, helmReadOnly: true, ghApiReadOnly: true }),
    );

    expect(await permissionStatus("gh issue list")).toBe("allow");
    expect(await permissionStatus("helm list")).toBe("allow");
    expect(await permissionStatus("gh api user")).toBe("allow");
    expect(await permissionStatus("gh issue list; gh repo delete acme/widgets")).toBe("ask");
  });

  test("does not override OpenCode permissions when profiles are disabled", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");
    expect(await permissionStatus("gh issue list")).toBe("ask");
    expect(await permissionStatus("helm list")).toBe("ask");
  });
});
