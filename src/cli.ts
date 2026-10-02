import { initBundledBashParser } from "./shell.js";
import { Command, CommanderError, InvalidArgumentError } from "commander";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { PolicyStartupError } from "./policy/config.js";
import { createExplainTrace, renderExplainTrace } from "./policy/trace.js";
import { evaluateLoadedPolicies, loadPolicyRuntime } from "./policy/runtime.js";
import { nodeExecutableFilesystem } from "./policy/filesystem.js";

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  try {
    await createProgram().parseAsync([...argv], { from: "user" });
  } catch (error) {
    if (error instanceof CommanderError && error.exitCode === 0) return;
    throw error;
  }
}

export function createProgram(): Command {
  const program = new Command()
    .name("safety-core")
    .description("Inspect the safety-core policy configuration and explain Bash policy decisions.")
    .option("--config <path>", "load configuration from an explicit path", nonEmptyConfigPath)
    .exitOverride();

  program
    .command("validate")
    .description("print the canonical paths and digests of active policy sources")
    .action(async () => {
      const runtime = await loadPolicyRuntime(process.cwd(), process.env, program.opts<{ config?: string }>().config);
      for (const source of runtime.policySet.sources) process.stdout.write(`${source.sha256}  ${source.canonicalPath}\n`);
    });

  program
    .command("explain")
    .description("explain the policy decision for one Bash source string")
    .option("--json", "emit the trace as JSON")
    .argument("<bash-source>", "Bash source to analyze")
    .action(async (source: string, options: { readonly json?: boolean }) => {
      const runtime = await loadPolicyRuntime(process.cwd(), process.env, program.opts<{ config?: string }>().config);
      await initBundledBashParser();
      const evaluation = evaluateLoadedPolicies(runtime, source, { kind: "verified", values: process.env as Record<string, string> }, { cwd: process.cwd(), executableFilesystem: nodeExecutableFilesystem });
      process.stdout.write(renderExplainTrace(createExplainTrace(runtime, evaluation), options.json === true));
    });

  return program;
}

function nonEmptyConfigPath(path: string): string {
  if (path.length === 0) throw new InvalidArgumentError("--config requires a non-empty path");
  return path;
}

if (process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url) {
  main().catch((error: unknown) => {
    if (error instanceof CommanderError) {
      process.exitCode = error.exitCode;
      return;
    }
    const message = error instanceof PolicyStartupError || error instanceof Error ? error.message : "safety-core failed";
    process.stderr.write(`safety-core: ${message}\n`);
    process.exitCode = 1;
  });
}
