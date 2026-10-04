import { afterAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { resolveBundledBashAssets } from "../src/index.ts";

const root = resolve(import.meta.dir, "..");
const fixtures: string[] = [];

afterAll(() => {
  for (const fixture of fixtures) rmSync(fixture, { force: true, recursive: true });
});

test("resolves generated source, packed core, and source adapter grammars independently of the runtime", () => {
  const runtimePath = join(root, "node_modules", "web-tree-sitter", "web-tree-sitter.wasm");
  const grammarPath = join(root, "packages", "core", "tree-sitter-bash.wasm");
  for (const modulePath of [
    join(root, "src", "shell.ts"),
    join(root, "packages", "core", "dist", "index.js"),
    join(root, "adapters", "claude-code", "bash_policy.ts"),
  ]) {
    expect(resolveBundledBashAssets(pathToFileURL(modulePath).href, runtimePath), modulePath).toEqual({
      grammarPath,
      runtimePath,
    });
  }
});

test("property: standalone bundle roots resolve their grammar across 1,024 caller depths", () => {
  const fixture = mkdtempSync(join(tmpdir(), "safety-core-bundled-assets-"));
  fixtures.push(fixture);
  const grammarPath = join(fixture, "tree-sitter-bash.wasm");
  const runtimePath = join(fixture, "web-tree-sitter.wasm");
  writeFileSync(grammarPath, "grammar");
  writeFileSync(runtimePath, "runtime");

  for (let seed = 0; seed < 1_024; seed++) {
    const depth = seed % 10;
    const directory = join(fixture, ...Array.from({ length: depth }, (_, index) => `nested-${seed}-${index}`));
    mkdirSync(directory, { recursive: true });
    const moduleUrl = pathToFileURL(join(directory, "adapter.mjs")).href;
    expect(resolveBundledBashAssets(moduleUrl, runtimePath), `seed ${seed}`).toEqual({ grammarPath, runtimePath });
  }
});
