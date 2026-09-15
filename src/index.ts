// Public entrypoint of the LLM safety-hook shared core. Adapters should
// import from here rather than reaching into individual modules.
// OpenCode consumes the configuration-driven Bash evaluator. Compatibility
// analyzers remain exported until Pi and Claude Code migrate in later slices.

export * from "./patterns.js";
export * from "./messages.js";
export {
  basename,
  assertBashParserInitialized,
  discoverWasmDir,
  initBashParser,
  isBashParserFailure,
  isBashParserInitialized,
  matchesAnyGlob,
  parseBash,
  parseBashProgram,
} from "./shell.js";
export { BashParserFailure } from "./shell.js";
export type { Redirect, SimpleCommand } from "./shell.js";
export type {
  BashAssignment,
  BashCommand,
  BashCommandSubstitutionWord,
  BashConcatenationWord,
  BashExpansionWord,
  BashFunction,
  BashGroup,
  BashIf,
  BashList,
  BashLiteralWord,
  BashParseFailure,
  BashPipeline,
  BashProgram,
  BashRedirect,
  BashRedirectKind,
  BashStatement,
  BashSubshell,
  BashUnsupported,
  BashUnsupportedWord,
  BashWord,
  SourceSpan,
} from "./bash/cst.js";
export * from "./secrets.js";
export * from "./github.js";
export * from "./kubectl.js";
export * from "./authorization.js";
export { analyzeSecretReadInvocation } from "./bash/policies/secrets.js";
export { analyzeGithubHttpInvocation } from "./bash/policies/github.js";
export { analyzeKubectlInvocation } from "./bash/policies/kubectl.js";
export { analyzeGhApiInvocation } from "./bash/policies/gh-api.js";
export { analyzeGhPrCreateInvocation } from "./bash/policies/gh-pr-create.js";
export * from "./gh.js";
export * from "./read-only-cli.js";
export * from "./gh-pr-create.js";
export * from "./audit.js";
export * from "./judge.js";
export * from "./config.js";
