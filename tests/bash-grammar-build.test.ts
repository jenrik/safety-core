import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  applyPatchFile,
  parseUnifiedPatch,
  patchedGrammarSha256,
  treeSitterBashVersion,
  treeSitterCliVersion,
} from "../scripts/build-bash-grammar.ts";

const root = resolve(import.meta.dir, "..");
const patch = readFileSync(join(root, "patches", "tree-sitter-bash-time-coproc.patch"), "utf8");
const patchFiles = parseUnifiedPatch(patch);

test("the pinned patch adds the exact Bash time and coprocess grammar forms", () => {
  expect(patchFiles.map((file) => file.path)).toEqual(["grammar.js", "src/scanner.c"]);
  const grammar = applyPatchFile(
    readFileSync(join(root, "node_modules", "tree-sitter-bash", "grammar.js"), "utf8"),
    patchFiles[0]!,
  );
  const scanner = applyPatchFile(
    readFileSync(join(root, "node_modules", "tree-sitter-bash", "src", "scanner.c"), "utf8"),
    patchFiles[1]!,
  );
  expect(grammar).toContain("time_statement: $ => prec.right(choice(");
  expect(grammar).toContain("coproc_statement: $ => prec.right(seq(");
  expect(grammar).toContain("field('posix', $.time_portability_option)");
  expect(grammar).toContain("$._pipeline_element");
  expect(scanner).toContain("TIME_PORTABILITY_OPTION");
  expect(scanner).toContain("if (valid_symbols[TIME_PORTABILITY_OPTION])");
});

test("property: every required patch context rejects 1,024 source drifts", () => {
  for (let seed = 0; seed < 1_024; seed++) {
    const file = patchFiles[seed % patchFiles.length]!;
    const hunk = file.hunks[(seed >> 1) % file.hunks.length]!;
    const expected = hunk.lines
      .filter((line) => line.startsWith(" ") || line.startsWith("-"))
      .map((line) => line.slice(1));
    const lineOffset = seed % expected.length;
    const sourcePath = join(root, "node_modules", "tree-sitter-bash", ...file.path.split("/"));
    const source = readFileSync(sourcePath, "utf8").split("\n");
    source[hunk.oldStart - 1 + lineOffset] = `${source[hunk.oldStart - 1 + lineOffset]} drift-${seed}`;
    expect(() => applyPatchFile(source.join("\n"), file), `seed ${seed}`).toThrow(
      "grammar patch no longer applies cleanly",
    );
  }
});

test("the native build stages the checksum-verified, version-pinned core grammar", () => {
  const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  expect(manifest.dependencies["tree-sitter-bash"]).toBe(treeSitterBashVersion);
  expect(manifest.devDependencies["tree-sitter-cli"]).toBe(treeSitterCliVersion);
  const grammar = join(root, "packages", "core", "tree-sitter-bash.wasm");
  expect(existsSync(grammar)).toBe(true);
  expect(createHash("sha256").update(readFileSync(grammar)).digest("hex")).toBe(patchedGrammarSha256);
});
