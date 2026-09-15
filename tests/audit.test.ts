import { expect, test } from "bun:test";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { appendAuditRecord } from "../src/index.ts";

test("audit sinks correct pre-existing permissions and serialize only declared fields", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-audit-"));
  const directory = join(root, "agent");
  const path = join(directory, "kubectl-secret-audit.jsonl");
  mkdirSync(directory, { recursive: true, mode: 0o777 });
  writeFileSync(path, "", { mode: 0o666 });
  await appendAuditRecord(path, {
    timestamp: "2026-09-15T00:00:00.000Z",
    kubectl_subcommand: "get",
    resource: "secret",
    command_length: 27,
    raw_command: "CANARY_VALUE=never-serialize",
  } as never);
  expect(statSync(directory).mode & 0o777).toBe(0o700);
  expect(statSync(path).mode & 0o777).toBe(0o600);
  const record = readFileSync(path, "utf8");
  expect(record).toContain('"resource":"secret"');
  expect(record).not.toContain("CANARY_VALUE");
});
