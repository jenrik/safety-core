import { initBundledBashParser } from "./shell.js";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { PolicyStartupError } from "./policy/config.js";
import { createExplainTrace, renderExplainTrace } from "./policy/trace.js";
import { evaluateLoadedPolicies, loadPolicyRuntime } from "./policy/runtime.js";
import { nodeExecutableFilesystem } from "./policy/filesystem.js";

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const { configPath, command, rest } = parseArguments(argv);
  if (command !== "validate" && command !== "explain") throw new Error(usage());
  const json = rest[0] === "--json";
  const sourceArguments = rest.slice(json ? 1 : 0);
  if (command === "explain" && (sourceArguments[0] !== "--" || sourceArguments.length !== 2)) {
    throw new Error(`usage: safety-core [--config <path>] explain [--json] -- <bash-source>`);
  }
  if (command === "validate" && sourceArguments.length !== 0) throw new Error("usage: safety-core [--config <path>] validate");

  const runtime = await loadPolicyRuntime(process.cwd(), process.env, configPath);
  if (command === "validate") {
    for (const source of runtime.policySet.sources) process.stdout.write(`${source.sha256}  ${source.canonicalPath}\n`);
    return;
  }
  await initBundledBashParser();
  const evaluation = evaluateLoadedPolicies(runtime, sourceArguments[1]!, { kind: "verified", values: process.env as Record<string, string> }, { cwd: process.cwd(), executableFilesystem: nodeExecutableFilesystem });
  process.stdout.write(renderExplainTrace(createExplainTrace(runtime, evaluation), json));
}

function parseArguments(argv: readonly string[]): { readonly configPath?: string; readonly command?: string; readonly rest: readonly string[] } {
  let configPath: string | undefined;
  const argumentsWithoutGlobalOptions: string[] = [];
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]!;
    if (argument === "--") {
      argumentsWithoutGlobalOptions.push(...argv.slice(index));
      break;
    }
    if (argument === "--config" || argument.startsWith("--config=")) {
      if (configPath !== undefined) throw new Error("--config may only be specified once");
      const path = argument === "--config" ? argv[++index] : argument.slice("--config=".length);
      if (path === undefined || path.length === 0) throw new Error("--config requires a path");
      configPath = path;
      continue;
    }
    argumentsWithoutGlobalOptions.push(argument);
  }
  const [command, ...rest] = argumentsWithoutGlobalOptions;
  return Object.freeze({ ...(configPath === undefined ? {} : { configPath }), ...(command === undefined ? {} : { command }), rest: Object.freeze(rest) });
}

function usage(): string {
  return "usage: safety-core [--config <path>] validate | safety-core [--config <path>] explain [--json] -- <bash-source>";
}

if (process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof PolicyStartupError || error instanceof Error ? error.message : "safety-core failed";
    process.stderr.write(`safety-core: ${message}\n`);
    process.exitCode = 1;
  });
}
