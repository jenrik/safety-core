import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Command, CommanderError, InvalidArgumentError } from "commander";
import { PolicyStartupError } from "./policy/config.js";
import { parsePolicyDocument, validatePolicyStateReachability } from "./policy/dsl/validate.js";
import {
  buildExplainEnvironment,
  type ExplainEnvironmentAssignment,
  type ExplainEnvironmentMode,
} from "./policy/explain.js";
import { nodeExecutableFilesystem } from "./policy/filesystem.js";
import { evaluateLoadedPolicies, loadPolicyRuntime } from "./policy/runtime.js";
import { createExplainTrace, renderExplainTrace } from "./policy/trace.js";
import { initBundledBashParser } from "./shell.js";

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
    .option("--config <path>", "load global configuration from an explicit path", nonEmptyPath("--config"))
    .option(
      "--project-config <path>",
      "load project configuration from an explicit path",
      nonEmptyPath("--project-config"),
    )
    .exitOverride();

  program
    .command("validate")
    .description("print the canonical paths and digests of active policy sources")
    .option("--cwd <path>", "discover project policies from this directory", existingDirectory)
    .action(async (options: { readonly cwd?: string }) => {
      const paths = program.opts<{ config?: string; projectConfig?: string }>();
      const runtime = await loadPolicyRuntime(
        options.cwd ?? process.cwd(),
        process.env,
        paths.config,
        paths.projectConfig,
      );
      for (const source of runtime.policySet.sources)
        process.stdout.write(`${source.sha256}  ${source.canonicalPath}\n`);
    });

  program
    .command("policy")
    .description("inspect standalone declarative policy sources")
    .command("validate")
    .description("validate a declarative policy schema and state reachability")
    .argument("<path>", "declarative .policy.json source")
    .action((path: string) => {
      const canonicalPath = canonicalPolicyPath(path);
      try {
        validatePolicyStateReachability(parsePolicyDocument(readFileSync(canonicalPath, "utf8")));
      } catch (error) {
        if (error instanceof PolicyStartupError) throw error;
        const detail = error instanceof Error ? `invalid DSL policy: ${error.message}` : "invalid DSL policy";
        throw new PolicyStartupError(canonicalPath, detail, error);
      }
      process.stdout.write(`${canonicalPath}: valid\n`);
    });

  program
    .command("test")
    .description("run a colocated <policy>.test.ts suite with its policy enabled")
    .argument("<path>", "policy test source ending in .test.ts")
    .action((path: string) => {
      const testPath = canonicalPolicyTestPath(path);
      const policyPath = policyPathForTest(testPath);
      const preload = policyTestPreloadPath();
      const result = spawnSync("bun", ["test", "--preload", preload, testPath], {
        stdio: "inherit",
        env: {
          ...process.env,
          SAFETY_CORE_POLICY_TEST_FILE: testPath,
          SAFETY_CORE_POLICY_TEST_POLICY: policyPath,
        },
      });
      if (result.error !== undefined) throw result.error;
      process.exitCode = result.status ?? 1;
    });

  program
    .command("explain")
    .description("explain the policy decision for one Bash source string")
    .option("--json", "emit the trace as JSON")
    .option(
      "--cwd <path>",
      "evaluate relative to this directory and discover project policies from it",
      existingDirectory,
    )
    .option(
      "--env-var <name=value>",
      "define a known policy-evaluation environment value (repeatable)",
      collectEnvironmentAssignment,
      [] as readonly ExplainEnvironmentAssignment[],
    )
    .option(
      "--env-mode <mode>",
      "how unspecified names are treated: verified (proven unset) or filtered (unknown)",
      parseEnvironmentMode,
      "verified" as ExplainEnvironmentMode,
    )
    .option("--inherit-env", "capture the ambient process environment before applying --env-var")
    .argument("<bash-source>", "Bash source to analyze")
    .action(
      async (
        source: string,
        options: {
          readonly json?: boolean;
          readonly cwd?: string;
          readonly envVar: readonly ExplainEnvironmentAssignment[];
          readonly envMode: ExplainEnvironmentMode;
          readonly inheritEnv?: boolean;
        },
      ) => {
        const paths = program.opts<{ config?: string; projectConfig?: string }>();
        const cwd = options.cwd ?? process.cwd();
        // Config discovery may consult the ambient environment; policy
        // evaluation itself is hermetic and driven only by the flags.
        const runtime = await loadPolicyRuntime(cwd, process.env, paths.config, paths.projectConfig);
        await initBundledBashParser();
        const evaluation = evaluateLoadedPolicies(
          runtime,
          source,
          buildExplainEnvironment({
            assignments: options.envVar,
            mode: options.envMode,
            inheritEnv: options.inheritEnv === true,
            ambient: process.env,
          }),
          { cwd, executableFilesystem: nodeExecutableFilesystem },
        );
        process.stdout.write(renderExplainTrace(createExplainTrace(runtime, evaluation), options.json === true));
      },
    );

  return program;
}

function nonEmptyPath(option: string): (path: string) => string {
  return (path) => {
    if (path.length === 0) throw new InvalidArgumentError(`${option} requires a non-empty path`);
    return path;
  };
}

function existingDirectory(path: string): string {
  if (path.length === 0) throw new InvalidArgumentError("--cwd requires a non-empty path");
  const resolved = resolve(path);
  let isDirectory = false;
  try {
    isDirectory = statSync(resolved).isDirectory();
  } catch {
    isDirectory = false;
  }
  if (!isDirectory) throw new InvalidArgumentError(`--cwd is not a directory: ${path}`);
  return resolved;
}

function parseEnvironmentAssignment(value: string): ExplainEnvironmentAssignment {
  const separator = value.indexOf("=");
  if (separator <= 0) throw new InvalidArgumentError("--env-var requires NAME=VALUE with a non-empty name");
  const name = value.slice(0, separator);
  const assignmentValue = value.slice(separator + 1);
  if (name.includes("\0") || assignmentValue.includes("\0"))
    throw new InvalidArgumentError("--env-var must not contain NUL bytes");
  return Object.freeze({ name, value: assignmentValue });
}

function collectEnvironmentAssignment(
  value: string,
  previous: readonly ExplainEnvironmentAssignment[],
): readonly ExplainEnvironmentAssignment[] {
  return [...previous, parseEnvironmentAssignment(value)];
}

function parseEnvironmentMode(value: string): ExplainEnvironmentMode {
  if (value !== "verified" && value !== "filtered")
    throw new InvalidArgumentError("--env-mode must be 'verified' or 'filtered'");
  return value;
}

function canonicalPolicyPath(path: string): string {
  if (!path.endsWith(".policy.json"))
    throw new PolicyStartupError(path, "declarative policy source must use the exact .policy.json extension");
  try {
    return realpathSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot canonicalize policy source", error);
  }
}

function canonicalPolicyTestPath(path: string): string {
  if (!path.endsWith(".test.ts"))
    throw new PolicyStartupError(path, "policy test source must use the exact .test.ts extension");
  try {
    return realpathSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot canonicalize policy test source", error);
  }
}

function policyPathForTest(testPath: string): string {
  const stem = testPath.slice(0, -".test.ts".length);
  const candidates = [".json", ".mjs"].map((extension) => `${stem}${extension}`).filter(existsSync);
  if (candidates.length !== 1) {
    throw new PolicyStartupError(
      testPath,
      candidates.length === 0
        ? `cannot find policy under test; expected ${stem}.json or ${stem}.mjs`
        : `policy test is ambiguous; both ${stem}.json and ${stem}.mjs exist`,
    );
  }
  return realpathSync(candidates[0]!);
}

function policyTestPreloadPath(): string {
  const besideCli = fileURLToPath(new URL("./test-preload.js", import.meta.url));
  if (existsSync(besideCli)) return besideCli;
  const sourceTree = fileURLToPath(new URL("./test-preload.ts", import.meta.url));
  if (existsSync(sourceTree)) return sourceTree;
  const nixSourceTree = fileURLToPath(new URL("../src/test-preload.ts", import.meta.url));
  if (existsSync(nixSourceTree)) return nixSourceTree;
  throw new Error("safety-core policy test setup is not installed");
}

if (process.argv[1] && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url) {
  main().catch((error: unknown) => {
    if (error instanceof CommanderError) {
      process.exitCode = error.exitCode;
      return;
    }
    const message =
      error instanceof PolicyStartupError || error instanceof Error ? error.message : "safety-core failed";
    process.stderr.write(`safety-core: ${message}\n`);
    process.exitCode = 1;
  });
}
