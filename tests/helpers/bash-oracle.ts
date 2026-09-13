import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface BashOracleTrace {
  readonly argv: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
}

export interface BashOracleFinalBinding {
  readonly kind: "set" | "unset";
  readonly exported: boolean;
}

export interface BashOracleWithFinalBindings {
  readonly trace: readonly BashOracleTrace[];
  readonly finalBindings: Readonly<Record<string, BashOracleFinalBinding>>;
}

const recordType = "record";
const finalType = "final";

/**
 * Runs a script in an empty environment with only known test values and an
 * executable command recorder on PATH. Neither target commands nor arbitrary
 * inherited variables are available to the script.
 */
export async function runBashOracle(
  source: string,
  knownEnvironment: Readonly<Record<string, string>> = {},
): Promise<readonly BashOracleTrace[]> {
  return (await runOracle(source, knownEnvironment)).trace;
}

/** Records only set/unset/exported state for selected final shell bindings. */
export async function runBashOracleWithFinalBindings(
  source: string,
  knownEnvironment: Readonly<Record<string, string>>,
  finalBindingNames: readonly string[],
): Promise<BashOracleWithFinalBindings> {
  assertBindingNames(finalBindingNames);
  const result = await runOracle(`${source}\n${finalSnapshotScript}`, knownEnvironment, finalBindingNames);
  if (!result.finalBindings) throw new Error("Invalid Bash oracle trace");
  return Object.freeze({ trace: result.trace, finalBindings: result.finalBindings });
}

/** Compare trace contents without including recorded argv or environment values in failures. */
export function assertEquivalentOracleTrace(
  actual: readonly BashOracleTrace[],
  expected: readonly BashOracleTrace[],
): void {
  assertTraceShape(actual);
  assertTraceShape(expected);
  if (actual.length !== expected.length) throw new Error("Redacted Bash oracle trace mismatch: record count");
  for (let index = 0; index < actual.length; index++) {
    const left = actual[index]!;
    const right = expected[index]!;
    if (!sameStrings(left.argv, right.argv) || !sameEnvironment(left.environment, right.environment)) {
      throw new Error("Redacted Bash oracle trace mismatch: record contents");
    }
  }
}

/** Compare redacted set/unset/export state without rendering binding values. */
export function assertEquivalentOracleFinalBindings(
  actual: Readonly<Record<string, BashOracleFinalBinding>>,
  expected: Readonly<Record<string, BashOracleFinalBinding>>,
): void {
  const actualNames = Object.keys(actual).sort();
  const expectedNames = Object.keys(expected).sort();
  if (!sameStrings(actualNames, expectedNames)) throw new Error("Redacted Bash oracle final-binding mismatch: names");
  for (const name of actualNames) {
    const left = actual[name]!;
    const right = expected[name]!;
    if (left.kind !== right.kind || left.exported !== right.exported) {
      throw new Error("Redacted Bash oracle final-binding mismatch: state");
    }
  }
}

async function runOracle(
  source: string,
  knownEnvironment: Readonly<Record<string, string>>,
  finalBindingNames: readonly string[] = [],
): Promise<{ readonly trace: readonly BashOracleTrace[]; readonly finalBindings?: Readonly<Record<string, BashOracleFinalBinding>> }> {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-oracle-"));
  const tracePath = join(directory, "trace");
  const shimPath = join(directory, "record-command");
  const bashPath = Bun.which("bash");
  if (!bashPath) throw new Error("Bash is required for the oracle test fixture");

  try {
    writeFileSync(shimPath, `#!${bashPath}
set -eu
names=()
# compgen is optional in Bash builds, while export -p is always available.
while IFS= read -r declaration; do
  case "$declaration" in *=*) ;; *) continue ;; esac
  name="\${declaration#declare -* }"
  name="\${name%%=*}"
  case "$name" in
    BASH_ENV|BASH_ORACLE_*|ENV|PATH|PWD|SHLVL|_) continue ;;
  esac
  names+=("$name")
done < <(export -p)
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
        ...knownEnvironment,
        PATH: directory,
        BASH_ENV: "/dev/null",
        ENV: "/dev/null",
        BASH_ORACLE_TRACE: tracePath,
        BASH_ORACLE_FINAL_BINDINGS: finalBindingNames.join(","),
      },
      stdout: "ignore",
      stderr: "ignore",
    });
    const exitCode = await process.exited;
    if (exitCode !== 0) throw new Error(`Bash oracle script failed with status ${exitCode}`);

    return parseTrace(readFileSync(tracePath), finalBindingNames);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

function parseTrace(
  contents: Buffer,
  finalBindingNames: readonly string[],
): { readonly trace: readonly BashOracleTrace[]; readonly finalBindings?: Readonly<Record<string, BashOracleFinalBinding>> } {
  const fields = contents.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  const trace: BashOracleTrace[] = [];
  let finalBindings: Readonly<Record<string, BashOracleFinalBinding>> | undefined;
  let offset = 0;
  while (offset < fields.length) {
    const type = fields[offset++];
    if (type === finalType) {
      if (finalBindings || finalBindingNames.length === 0) throw new Error("Invalid Bash oracle trace");
      const bindingCount = parseCount(fields[offset++]);
      if (bindingCount !== finalBindingNames.length) throw new Error("Invalid Bash oracle trace");
      const bindings: Record<string, BashOracleFinalBinding> = {};
      for (let index = 0; index < bindingCount; index++) {
        const name = fields[offset++];
        const kind = fields[offset++];
        const exported = fields[offset++];
        if (!name || !isSafeBindingName(name) || (kind !== "set" && kind !== "unset") || (exported !== "0" && exported !== "1")) {
          throw new Error("Invalid Bash oracle trace");
        }
        bindings[name] = Object.freeze({ kind, exported: exported === "1" });
      }
      if (!sameStrings(Object.keys(bindings).sort(), [...finalBindingNames].sort())) throw new Error("Invalid Bash oracle trace");
      finalBindings = Object.freeze(bindings);
      continue;
    }
    if (type !== recordType) throw new Error("Invalid Bash oracle trace");
    const argvLength = parseCount(fields[offset++]);
    const argv = fields.slice(offset, offset + argvLength);
    offset += argvLength;
    const environmentLength = parseCount(fields[offset++]);
    const environment: Record<string, string> = {};
    for (let index = 0; index < environmentLength; index++) {
      const name = fields[offset++];
      const value = fields[offset++];
      if (name === undefined || value === undefined || !isSafeBindingName(name) || name.startsWith("BASH_ORACLE_") || name === "PATH") {
        throw new Error("Invalid Bash oracle trace");
      }
      environment[name] = value;
    }
    trace.push(Object.freeze({ argv: Object.freeze(argv), environment: Object.freeze(environment) }));
  }
  if (finalBindingNames.length > 0 && !finalBindings) throw new Error("Invalid Bash oracle trace");
  return Object.freeze({ trace: Object.freeze(trace), ...(finalBindings ? { finalBindings } : {}) });
}

function parseCount(value: string | undefined): number {
  if (!value || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("Invalid Bash oracle trace");
  return Number(value);
}

function assertTraceShape(trace: readonly BashOracleTrace[]): void {
  for (const record of trace) {
    if (!record || !Array.isArray(record.argv) || !record.argv.every((value) => typeof value === "string")) {
      throw new Error("Invalid Bash oracle trace shape");
    }
    for (const [name, value] of Object.entries(record.environment)) {
      if (!isSafeBindingName(name) || name.startsWith("BASH_ORACLE_") || name === "PATH" || typeof value !== "string") {
        throw new Error("Invalid Bash oracle trace shape");
      }
    }
  }
}

function assertBindingNames(names: readonly string[]): void {
  if (new Set(names).size !== names.length || names.some((name) => !isSafeBindingName(name))) {
    throw new Error("Invalid Bash oracle final-binding request");
  }
}

function isSafeBindingName(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameEnvironment(left: Readonly<Record<string, string>>, right: Readonly<Record<string, string>>): boolean {
  const leftNames = Object.keys(left).sort();
  const rightNames = Object.keys(right).sort();
  return sameStrings(leftNames, rightNames) && leftNames.every((name) => left[name] === right[name]);
}

const finalSnapshotScript = `
IFS=, read -r -a bash_oracle_final_names <<< "$BASH_ORACLE_FINAL_BINDINGS"
{
  printf '%s\\0' '${finalType}' "\${#bash_oracle_final_names[@]}"
  for name in "\${bash_oracle_final_names[@]}"; do
    if [[ -v "$name" ]]; then
      exported=0
      declaration=$(declare -p "$name" 2>/dev/null)
      case "$declaration" in declare\\ -*x*) exported=1 ;; esac
      printf '%s\\0%s\\0%s\\0' "$name" set "$exported"
    else
      printf '%s\\0%s\\0%s\\0' "$name" unset 0
    fi
  done
} >> "$BASH_ORACLE_TRACE"
true
`;
