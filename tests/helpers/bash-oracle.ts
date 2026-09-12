import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface BashOracleTrace {
  readonly argv: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
}

const recordType = "record";

/**
 * Runs a script in an empty environment with only known test values and an
 * executable command recorder on PATH. Neither target commands nor arbitrary
 * inherited variables are available to the script.
 */
export async function runBashOracle(
  source: string,
  knownEnvironment: Readonly<Record<string, string>> = {},
): Promise<readonly BashOracleTrace[]> {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-oracle-"));
  const tracePath = join(directory, "trace");
  const shimPath = join(directory, "record-command");
  const bashPath = Bun.which("bash");
  if (!bashPath) throw new Error("Bash is required for the oracle test fixture");

  try {
    writeFileSync(shimPath, `#!${bashPath}
set -eu
names=()
while IFS= read -r name; do
  case "$name" in
    BASH_ORACLE_*|PATH|PWD|SHLVL|_) continue ;;
  esac
  names+=("$name")
done < <(compgen -e)
{
  printf '%s\\0' '${recordType}' "$#"
  printf '%s\\0' "$@"
  printf '%s\\0' "\${#names[@]}"
  for name in "\${names[@]}"; do
    printf '%s\\0%s\\0' "$name" "\${!name}"
  done
} >> "$BASH_ORACLE_TRACE"
`);
    chmodSync(shimPath, 0o755);

    const process = Bun.spawn([bashPath, "--noprofile", "--norc", "-c", source], {
      env: {
        PATH: directory,
        BASH_ORACLE_TRACE: tracePath,
        ...knownEnvironment,
      },
      stdout: "ignore",
      stderr: "ignore",
    });
    const exitCode = await process.exited;
    if (exitCode !== 0) throw new Error("Bash oracle script failed");

    return parseTrace(readFileSync(tracePath));
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

function parseTrace(contents: Buffer): readonly BashOracleTrace[] {
  const fields = contents.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  const trace: BashOracleTrace[] = [];
  let offset = 0;
  while (offset < fields.length) {
    if (fields[offset++] !== recordType) throw new Error("Invalid Bash oracle trace");
    const argvLength = parseCount(fields[offset++]);
    const argv = fields.slice(offset, offset + argvLength);
    offset += argvLength;
    const environmentLength = parseCount(fields[offset++]);
    const environment: Record<string, string> = {};
    for (let index = 0; index < environmentLength; index++) {
      const name = fields[offset++];
      const value = fields[offset++];
      if (name === undefined || value === undefined) throw new Error("Truncated Bash oracle trace");
      environment[name] = value;
    }
    trace.push(Object.freeze({ argv: Object.freeze(argv), environment: Object.freeze(environment) }));
  }
  return Object.freeze(trace);
}

function parseCount(value: string | undefined): number {
  if (!value || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("Invalid Bash oracle trace");
  return Number(value);
}
