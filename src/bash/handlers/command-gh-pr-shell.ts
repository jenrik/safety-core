import { parseBashProgram } from "../../shell.js";
import type { BashStatement } from "../cst.js";
import type { CommandHandler } from "../dispatch.js";
import { indeterminate, policyDeny } from "../outcome.js";
import { denyGhPrCreate } from "../policies/gh-pr-create.js";
import { commandScript, knownArguments } from "./gh-utils.js";

/** Re-dispatch literal interpreter payloads; the child invocation owns its policy decision. */
export const ghPrCreateShellHandlers: readonly CommandHandler[] = Object.freeze(
  ["eval", "sh", "bash", "dash", "fish", "ksh", "zsh"].map((name) => Object.freeze({
    name,
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return indeterminate(context.span);
      const script = name === "eval" ? args.join(" ") : commandScript(args);
      if (!script && context.inPipeline) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      if (script && scriptContainsGhAttempt(script)) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      return script ? context.continueWith(script) : indeterminate(context.span);
    },
  })),
);

function denied(context: Parameters<CommandHandler["handle"]>[1], reason: string) {
  return policyDeny(context.span, denyGhPrCreate(reason).evidence);
}

function scriptContainsGhAttempt(source: string): boolean {
  const program = parseBashProgram(source);
  return program.kind === "program" && program.statements.some(statementContainsGhAttempt);
}

function statementContainsGhAttempt(statement: BashStatement): boolean {
  if (statement.kind === "command") {
    const words = statement.words.map((word) => word.text);
    return words[0] === "gh" && ((words[1] === "pr" && ["create", "new"].includes(words[2] ?? "")) || words[1] === "api");
  }
  if (statement.kind === "function") return statementContainsGhAttempt(statement.body);
  if (statement.kind === "if") {
    return [...statement.condition, ...statement.consequent, ...statement.alternate].some(statementContainsGhAttempt);
  }
  return statement.statements.some(statementContainsGhAttempt);
}
