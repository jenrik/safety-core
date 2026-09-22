import { discoverWasmDir, initBashParser } from "./shell.js";
import { pathToFileURL } from "node:url";
import { PolicyStartupError } from "./policy/config.js";
import { createExplainTrace, renderExplainTrace } from "./policy/trace.js";
import { evaluateLoadedPolicies, loadPolicyRuntime } from "./policy/runtime.js";
import { nodeExecutableFilesystem } from "./policy/filesystem.js";

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const [command, ...rest] = argv;
  if (command !== "validate" && command !== "explain") throw new Error("usage: safety-core validate | safety-core explain [--json] -- <bash-source>");
  const json = rest[0] === "--json";
  const sourceArguments = rest.slice(json ? 1 : 0);
  if (command === "explain" && (sourceArguments[0] !== "--" || sourceArguments.length !== 2)) {
    throw new Error("usage: safety-core explain [--json] -- <bash-source>");
  }
  if (command === "validate" && sourceArguments.length !== 0) throw new Error("usage: safety-core validate");

  const runtime = await loadPolicyRuntime(process.cwd());
  if (command === "validate") {
    for (const source of runtime.policySet.sources) process.stdout.write(`${source.sha256}  ${source.canonicalPath}\n`);
    return;
  }
  await initBashParser(discoverWasmDir(import.meta.url));
  const evaluation = evaluateLoadedPolicies(runtime, sourceArguments[1]!, { kind: "verified", values: process.env as Record<string, string> }, { cwd: process.cwd(), executableFilesystem: nodeExecutableFilesystem });
  process.stdout.write(renderExplainTrace(createExplainTrace(runtime, evaluation), json));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof PolicyStartupError || error instanceof Error ? error.message : "safety-core failed";
    process.stderr.write(`safety-core: ${message}\n`);
    process.exitCode = 1;
  });
}
