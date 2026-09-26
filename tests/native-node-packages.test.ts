import { afterAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const packageDirectories = ["core", "opencode-v1", "pi", "claude-code"] as const;
const generatedTarballs: string[] = [];

function run(command: string, args: readonly string[], cwd: string, input?: string): string {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", input });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function pack(packageName: typeof packageDirectories[number]): string {
  const directory = join(root, "packages", packageName);
  const output = run("npm", ["pack", "--json"], directory);
  const filename = JSON.parse(output)[0]?.filename;
  if (typeof filename !== "string") throw new Error(`npm pack did not produce ${packageName}`);
  const tarball = join(directory, filename);
  generatedTarballs.push(tarball);
  return tarball;
}

afterAll(() => {
  for (const tarball of generatedTarballs) rmSync(tarball, { force: true });
});

test("packed native packages exclude policy sources", () => {
  for (const packageName of packageDirectories) {
    const entries = run("tar", ["-tf", pack(packageName)], root).trim().split("\n");
    expect(entries).not.toContain("package/policies/");
    expect(entries.some((entry) => /(^|\/)policies\/|\.policy\.(?:[cm]?[jt]s|json)$/u.test(entry))).toBe(false);
  }
});

test("Pi packages declare one native extension and keep host modules development-only", () => {
  const manifest = JSON.parse(run("node", ["--input-type=module", "--eval", `
    import manifest from "./packages/pi/package.json" with { type: "json" };
    console.log(JSON.stringify(manifest));
  `], root));
  expect(manifest.pi).toEqual({ extensions: ["./extensions/extension.js"] });
  expect(manifest.dependencies).toEqual({ "@safety-core/core": "0.0.0" });
  expect(Object.keys(manifest.devDependencies).sort()).toEqual([
    "@earendil-works/pi-ai",
    "@earendil-works/pi-coding-agent",
    "@earendil-works/pi-tui",
    "typebox",
  ]);
});

test("packed packages install and expose the OpenCode v1 server and TUI forms", () => {
  const core = pack("core");
  const opencode = pack("opencode-v1");
  const pi = pack("pi");
  const claude = pack("claude-code");
  const installation = mkdtempSync(join(tmpdir(), "safety-core-native-package-"));
  try {
    run("npm", ["init", "--yes"], installation);
    run("npm", ["install", "--offline", "--ignore-scripts", core, opencode, pi, claude], installation);
    const result = run("node", ["--input-type=module", "--eval", `
      import server from "@safety-core/opencode-v1/server";
      import tui from "@safety-core/opencode-v1/tui";
      import { initBundledBashParser, parseBashProgram } from "@safety-core/core";
      await initBundledBashParser();
      const parsed = parseBashProgram("printf package-installed");
      console.log(JSON.stringify({
        id: server.id,
        server: typeof server.server,
        tuiId: tui.id,
        tui: typeof tui.tui,
        hasTool: "tool" in tui,
        parsed: parsed.kind,
      }));
    `], installation);
    expect(JSON.parse(result)).toEqual({
      id: "safety-core.policy-reload",
      server: "function",
      tuiId: "safety-core.policy-reload",
      tui: "function",
      hasTool: false,
      parsed: "program",
    });
    expect(run(join(installation, "node_modules", ".bin", "safety-core-claude-github-raw-redirect"), [], installation,
      JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://api.github.com/user" } })),
    ).toContain('"permissionDecision":"deny"');
  } finally {
    rmSync(installation, { force: true, recursive: true });
  }
}, 30_000);

test("packed Pi extension retains TUI-only settings and secret-read contracts", () => {
  const core = pack("core");
  const pi = pack("pi");
  const installation = mkdtempSync(join(tmpdir(), "safety-core-pi-package-"));
  try {
    run("npm", ["init", "--yes"], installation);
    run("npm", ["install", "--offline", "--ignore-scripts", core, pi], installation);
    writePiHostStubs(installation);
    const result = run("node", ["--input-type=module", "--eval", `
      import { createPiExtension, resolvePiSessionSettings } from "@safety-core/pi/extensions/extension.js";
      const handlers = new Map();
      const commands = new Map();
      const tools = [];
      const notices = [];
      createPiExtension({
        on: (name, handler) => handlers.set(name, handler),
        registerTool: (tool) => tools.push(tool.name),
        registerCommand: (name, command) => commands.set(name, command),
        appendEntry() {},
      }, {
        runtime: Promise.resolve({ config: { pi: { autoApprove: false } } }),
        evaluatePolicies: () => ({ decision: "defer", analysis: { complete: false }, events: [], traces: [] }),
      });
      await handlers.get("session_start")({}, { cwd: process.cwd() });
      const read = await handlers.get("tool_call")({ toolName: "read", input: { path: "credentials.json" } }, { ui: { notify() {} } });
      await commands.get("safety-core").handler("", { mode: "json", ui: { notify: (message, level) => notices.push([message, level]) } });
      for (let seed = 0; seed < 1024; seed++) {
        const entries = Array.from({ length: 1 + seed % 16 }, (_, index) => ({
          type: "custom", customType: "safety-core-pi-settings",
          data: { autoApprove: (seed + index) % 2 === 0, judgeModel: (seed + index) % 3 === 0 ? null : "provider/model-" + seed + "-" + index },
        }));
        const last = entries.at(-1).data;
        const settings = resolvePiSessionSettings(entries, { autoApprove: false, judgeModel: "configured/model" });
        if (settings.autoApprove !== last.autoApprove || settings.judgeModel !== (last.judgeModel ?? undefined)) throw new Error("seed " + seed);
      }
      console.log(JSON.stringify({ tools, commands: [...commands.keys()], read, notices }));
    `], installation);
    expect(JSON.parse(result)).toEqual({
      tools: ["bash"],
      commands: ["safety-core"],
      read: { block: true, reason: expect.stringContaining("This file appears to contain secret values") },
      notices: [["/safety-core requires TUI mode", "error"]],
    });
  } finally {
    rmSync(installation, { force: true, recursive: true });
  }
}, 30_000);

test("property: both native OpenCode exports retain their distinct contracts across 1,024 checks", async () => {
  const server = (await import("@safety-core/opencode-v1/server")).default;
  const tui = (await import("@safety-core/opencode-v1/tui")).default;
  for (let seed = 0; seed < 1_024; seed++) {
    const plugin = seed % 2 === 0 ? server : tui;
    expect(plugin.id, `seed ${seed}`).toBe("safety-core.policy-reload");
    expect("server" in plugin, `seed ${seed}`).toBe(seed % 2 === 0);
    expect("tui" in plugin, `seed ${seed}`).toBe(seed % 2 === 1);
    expect("tool" in plugin, `seed ${seed}`).toBe(false);
  }
});

function writePiHostStubs(installation: string): void {
  writeModule(installation, "@earendil-works/pi-coding-agent", `
    export const createBashTool = () => ({ execute() {} });
    export const getSettingsListTheme = () => ({});
  `);
  writeModule(installation, "@earendil-works/pi-tui", `
    export class Container { addChild() {} render() { return []; } invalidate() {} }
    export class SettingsList { constructor() {} handleInput() {} }
    export class Text {}
  `);
  writeModule(installation, "typebox", `
    export const Type = { Object: (value) => value, String: () => ({}), Optional: (value) => value, Number: () => ({}) };
  `);
}

function writeModule(installation: string, name: string, source: string): void {
  const directory = join(installation, "node_modules", ...name.split("/"));
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "package.json"), JSON.stringify({ name, type: "module", exports: "./index.js" }));
  writeFileSync(join(directory, "index.js"), source);
}
