import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const files = ["prompt_handshake", "prompt_v1"];
const result = Bun.spawnSync({
  cmd: [
    "protoc",
    "-I",
    "proto",
    "--es_out=src/prompt/gen",
    "--es_opt=target=ts",
    "--plugin=protoc-gen-es=./node_modules/.bin/protoc-gen-es",
    ...files.map((file) => `proto/${file}.proto`),
  ],
  cwd: root,
  stdout: "inherit",
  stderr: "inherit",
});
if (result.exitCode !== 0) throw new Error("prompt protobuf generation failed");

// protoc-gen-es leaves an extra blank line at EOF; keep generated files diff-clean.
for (const file of files) {
  const path = resolve(root, "src/prompt/gen", `${file}_pb.ts`);
  writeFileSync(path, readFileSync(path, "utf8").replace(/\n+$/u, "\n"));
}
