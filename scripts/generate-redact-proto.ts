import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const result = Bun.spawnSync({
  cmd: [
    "protoc", "-I", "redact-service/proto",
    "--python_out=redact-service/src/safety_core_redact/gen",
    "--es_out=src/redact/gen", "--es_opt=target=ts",
    "--plugin=protoc-gen-es=./node_modules/.bin/protoc-gen-es",
    "redact-service/proto/handshake.proto", "redact-service/proto/redact_v1.proto",
  ],
  cwd: root,
  stdout: "inherit",
  stderr: "inherit",
});
if (result.exitCode !== 0) throw new Error("redaction protobuf generation failed");

// protoc-gen-es leaves an extra blank line at EOF; keep generated files diff-clean.
for (const name of ["handshake", "redact_v1"]) {
  const file = resolve(root, "src/redact/gen", `${name}_pb.ts`);
  writeFileSync(file, readFileSync(file, "utf8").replace(/\n+$/u, "\n"));
}
