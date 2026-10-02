import type { BashFunction } from "./cst.js";
import { modeledBindings, type Environment } from "./environment.js";
import { exportedBashFunctionName } from "./policy-environment.js";
import type { BashShellState } from "./state.js";
import { parseBashProgram } from "../shell.js";

export interface ImportedBashFunctions {
  readonly definitions: readonly BashFunction[];
  /** An unrecognized import makes coverage of this shell startup incomplete. */
  readonly invalid: boolean;
}

const importedDefinitions = new WeakSet<BashFunction>();

export function isImportedBashFunction(definition: BashFunction): boolean {
  return importedDefinitions.has(definition);
}

export function markImportedBashFunction(definition: BashFunction): void {
  importedDefinitions.add(definition);
}

/** Interpret the same exported entries Bash imports at startup, without executing them. */
export function importBashFunctions(environment: Environment, parent?: BashShellState): ImportedBashFunctions {
  const definitions: BashFunction[] = [];
  let invalid = false;
  for (const [key, binding] of Object.entries(modeledBindings(environment).values)) {
    const name = exportedBashFunctionName(key);
    if (!name || binding.kind === "unset") continue;
    if (parent?.missingFunctions.has(name)) {
      invalid = true;
      definitions.push(...(parent.functionCandidates.get(name) ?? []));
      continue;
    }
    if (binding.kind === "unknown" && parent?.functionCandidates.has(name) && !parent.missingFunctions.has(name)) {
      definitions.push(...parent.functionCandidates.get(name)!);
      continue;
    }
    if (binding.kind !== "known" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || !/^\(\) \{/.test(binding.value)) {
      invalid = true;
      continue;
    }
    const source = `${name}${binding.value}`;
    const parsed = parseBashProgram(source);
    const definition = parsed.kind === "program" && parsed.statements.length === 1 ? parsed.statements[0] : undefined;
    if (
      definition?.kind !== "function" ||
      definition.name !== name ||
      source.slice(definition.span.end).trim().length > 0
    ) {
      invalid = true;
      continue;
    }
    markImportedBashFunction(definition);
    definitions.push(definition);
  }
  return Object.freeze({ definitions: Object.freeze(definitions), invalid });
}
