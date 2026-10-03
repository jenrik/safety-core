import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const treeSitterBashVersion = "0.25.1";
export const treeSitterCliVersion = "0.26.11";
export const patchedGrammarSha256 = "e9d5f7c623675e6c02b35973350f7be8d87d74f6a6ca1a40701654623af31a06";

type PatchHunk = {
  readonly oldStart: number;
  readonly oldCount: number;
  readonly lines: readonly string[];
};

type PatchFile = {
  readonly path: string;
  readonly hunks: readonly PatchHunk[];
};

function patchPath(line: string, prefix: string): string {
  if (!line.startsWith(prefix)) throw new Error(`expected ${prefix} header in grammar patch`);
  const path = line.slice(prefix.length).split("\t", 1)[0]!;
  if (!/^[ab]\//u.test(path)) throw new Error(`unexpected grammar patch path: ${path}`);
  return path.slice(2);
}

function parseHunkHeader(line: string): { oldStart: number; oldCount: number } {
  const match = /^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@/u.exec(line);
  if (!match) throw new Error(`invalid grammar patch hunk: ${line}`);
  return { oldStart: Number(match[1]), oldCount: Number(match[2] ?? "1") };
}

export function parseUnifiedPatch(patch: string): readonly PatchFile[] {
  const lines = patch.split("\n");
  const files: PatchFile[] = [];
  let index = 0;

  while (index < lines.length) {
    if (!lines[index]!.startsWith("diff --git ")) {
      index++;
      continue;
    }
    index++;
    while (lines[index]?.startsWith("index ")) index++;
    const oldPath = patchPath(lines[index++]!, "--- ");
    const newPath = patchPath(lines[index++]!, "+++ ");
    if (oldPath !== newPath) throw new Error(`grammar patch renames ${oldPath} to ${newPath}`);
    const hunks: PatchHunk[] = [];
    while (index < lines.length && !lines[index]!.startsWith("diff --git ")) {
      const header = lines[index]!;
      if (!header.startsWith("@@ ")) {
        index++;
        continue;
      }
      const { oldStart, oldCount } = parseHunkHeader(header);
      index++;
      const hunkLines: string[] = [];
      while (index < lines.length && !lines[index]!.startsWith("@@ ") && !lines[index]!.startsWith("diff --git ")) {
        const line = lines[index++]!;
        if (line.startsWith("\\ No newline")) continue;
        if (line === "") {
          // The preserved patch has one unprefixed trailing context line.
          // Interpret it as an empty context line only when its hunk header
          // still requires an original source line.
          if (
            hunkLines.filter((candidate) => candidate.startsWith(" ") || candidate.startsWith("-")).length < oldCount
          ) {
            hunkLines.push(" ");
          }
          continue;
        }
        if (!/^[ +\-]/u.test(line)) throw new Error(`invalid grammar patch line: ${line}`);
        hunkLines.push(line);
      }
      hunks.push({ oldStart, oldCount, lines: hunkLines });
    }
    files.push({ path: oldPath, hunks });
  }
  return files;
}

export function applyPatchFile(source: string, file: PatchFile): string {
  const sourceLines = source.split("\n");
  let offset = 0;
  for (const hunk of file.hunks) {
    const start = hunk.oldStart - 1 + offset;
    const expected = hunk.lines
      .filter((line) => line.startsWith(" ") || line.startsWith("-"))
      .map((line) => line.slice(1));
    if (
      expected.length !== hunk.oldCount ||
      sourceLines.slice(start, start + expected.length).some((line, index) => line !== expected[index])
    ) {
      throw new Error(`grammar patch no longer applies cleanly to ${file.path} hunk at line ${hunk.oldStart}`);
    }
    const replacement = hunk.lines
      .filter((line) => line.startsWith(" ") || line.startsWith("+"))
      .map((line) => line.slice(1));
    sourceLines.splice(start, expected.length, ...replacement);
    offset += replacement.length - expected.length;
  }
  return sourceLines.join("\n");
}

async function run(command: readonly string[], cwd: string): Promise<void> {
  const process = Bun.spawn([...command], { cwd, stderr: "inherit", stdout: "inherit" });
  if ((await process.exited) !== 0) throw new Error(`${command.join(" ")} failed`);
}

export async function buildPatchedBashGrammar(root: string, outputPath: string): Promise<void> {
  if (
    existsSync(outputPath) &&
    createHash("sha256").update(readFileSync(outputPath)).digest("hex") === patchedGrammarSha256
  )
    return;
  rmSync(outputPath, { force: true });
  const grammarPackage = resolve(root, "node_modules", "tree-sitter-bash");
  const patch = readFileSync(resolve(root, "patches", "tree-sitter-bash-time-coproc.patch"), "utf8");
  const workDir = mkdtempSync(join(tmpdir(), "safety-core-tree-sitter-bash-"));
  const grammarDir = join(workDir, "tree-sitter-bash");
  try {
    cpSync(grammarPackage, grammarDir, { recursive: true });
    for (const file of parseUnifiedPatch(patch)) {
      const sourcePath = join(grammarDir, file.path);
      writeFileSync(sourcePath, applyPatchFile(readFileSync(sourcePath, "utf8"), file));
    }
    const cli = resolve(root, "node_modules", ".bin", process.platform === "win32" ? "tree-sitter.cmd" : "tree-sitter");
    await run([cli, "generate"], grammarDir);
    await run([cli, "build", "--wasm", "--output", outputPath], grammarDir);
    const digest = createHash("sha256").update(readFileSync(outputPath)).digest("hex");
    if (digest !== patchedGrammarSha256) {
      throw new Error(`generated tree-sitter-bash.wasm digest ${digest} does not match ${patchedGrammarSha256}`);
    }
  } finally {
    rmSync(workDir, { force: true, recursive: true });
  }
}
