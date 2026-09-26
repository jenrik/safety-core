import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const packageDirectories = ["core", "opencode-v1"] as const;
const generatedTarballs: string[] = [];

function run(command: string, args: readonly string[], cwd: string): string {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
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

test("packed packages install and expose the OpenCode v1 server and TUI forms", () => {
  const core = pack("core");
  const opencode = pack("opencode-v1");
  const installation = mkdtempSync(join(tmpdir(), "safety-core-native-package-"));
  try {
    run("npm", ["init", "--yes"], installation);
    run("npm", ["install", "--offline", "--ignore-scripts", core, opencode], installation);
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
  } finally {
    rmSync(installation, { force: true, recursive: true });
  }
});

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
