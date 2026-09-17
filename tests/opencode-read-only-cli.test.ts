import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { evaluateConfiguredBash, initBashParser, type BashConfiguredOptions } from "../src/index.ts";

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
  test("allows configured profile reads, hands gh api to its dedicated profile, and preserves compound prompts", async () => {
    writeFileSync(
      join(configHome, "safety-core", "profiles.json"),
      JSON.stringify({
        readOnlyBash: true,
        ghReadOnly: true,
        helmReadOnly: true,
        dockerReadOnly: true,
        kubectlReadOnly: true,
        npmReadOnly: true,
        podmanReadOnly: true,
        tofuReadOnly: true,
        ghApiReadOnly: true,
      }),
    );

    expect(await permissionStatus("gh version")).toBe("ask");
    expect(await permissionStatus("gh label list")).toBe("ask");
    expect(await permissionStatus("tea --help")).toBe("allow");
    expect(await permissionStatus("tea pr merge 3 --repo example/project -s merge")).toBe("ask");
    expect(await permissionStatus("git show --no-ext-diff HEAD | sha256sum && git diff --stat origin/main...origin/feature")).toBe("allow");
    expect(await permissionStatus("helm version")).toBe("allow");
    expect(await permissionStatus("docker image ls")).toBe("allow");
    expect(await permissionStatus("kubectl get pods -n default")).toBe("allow");
    expect(await permissionStatus("kubectl get pod -n default -o jsonpath='{.status.phase}'")).toBe("allow");
    expect(await permissionStatus("npm ls package --json")).toBe("allow");
    expect(await permissionStatus("podman network list")).toBe("allow");
    expect(await permissionStatus("tofu providers schema -json")).toBe("ask");
    expect(await permissionStatus("tofu -json providers schema")).toBe("ask");
    expect(await permissionStatus("gh api user")).toBe("ask");
    expect(await permissionStatus("GH_PAGER= gh api user")).toBe("ask");
    expect(await permissionStatus("gh issue list; gh repo delete acme/widgets")).toBe("ask");
    expect(await permissionStatus("docker ps")).toBe("ask");
    expect(await permissionStatus("./docker image ls")).toBe("ask");
    expect(await permissionStatus("NODE_OPTIONS=--require=./instrumentation.js npm ls package")).toBe("ask");
    expect(await permissionStatus("tofu providers lock")).toBe("ask");
    expect(await permissionStatus("helm env")).toBe("ask");
    expect(await permissionStatus("helm show readme chart")).toBe("ask");
    expect(await permissionStatus("npm query :root")).toBe("ask");
  });

  test("does not override OpenCode permissions when profiles are disabled", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");
    expect(await permissionStatus("gh issue list")).toBe("ask");
    expect(await permissionStatus("helm list")).toBe("ask");
  });

  test("does not auto-allow an unrelated base-handler read when only ghPrCreate is active", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({
      ghPrCreate: { enabled: true, allowedRepositories: ["acme/widgets"], allowedOrganizations: [] },
    }));
    expect(await permissionStatus("cat README.md")).toBe("ask");
  });

  test("uses one configured evaluator per Bash permission callback", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghReadOnly: true }));
    const { createOpenCodePlugin } = await import("../adapters/opencode.ts");
    let calls = 0;
    let environmentNames: string[] = [];
    const previousDebug = process.env.GH_DEBUG;
    const previousToken = process.env.GITHUB_TOKEN;
    process.env.GH_DEBUG = "policy-test";
    process.env.GITHUB_TOKEN = "excluded-policy-test-token";
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        calls++;
        environmentNames = options.initialEnvironment?.kind === "filtered" ? Object.keys(options.initialEnvironment.values) : [];
        expect(options).toMatchObject({ source: "gh version", initialEnvironment: { kind: "filtered" } });
        return evaluateConfiguredBash(options);
      },
    });
    try {
      const output = { status: "ask" };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "gh version" }, output);
      expect(output.status).toBe("ask");
      expect(calls).toBe(1);
      expect(environmentNames).toContain("GH_DEBUG");
      expect(environmentNames).not.toContain("GITHUB_TOKEN");
    } finally {
      if (previousDebug === undefined) delete process.env.GH_DEBUG; else process.env.GH_DEBUG = previousDebug;
      if (previousToken === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = previousToken;
    }
  });

  test("resolves current OpenCode permission events through the client", async () => {
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ readOnlyBash: true }));
    const { createOpenCodePlugin } = await import("../adapters/opencode.ts");
    const replies: unknown[] = [];
    const plugin = await createOpenCodePlugin({}, {
      permission: {
        reply: async (input: unknown) => { replies.push(input); },
      },
    } as never, "/workspace");
    await (plugin.event as Function)({
      event: {
        type: "permission.asked",
        properties: { id: "request-1", permission: "bash", patterns: ["tea --help"] },
      },
    });
    expect(replies).toEqual([{ directory: "/workspace", requestID: "request-1", reply: "once" }]);
  });
});
