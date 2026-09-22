// Public entrypoint of the LLM safety-hook shared core. Adapters should
// import from here rather than reaching into individual modules.
// Every harness consumes the configuration-driven Bash evaluator. Compatibility
// analyzers remain exported until the final cleanup slice removes old callers.

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
  parseBashProgram,
} from "./shell.js";
export { BashParserFailure } from "./shell.js";
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
export { analyzeGitReadOnlyInvocation } from "./bash/policies/git.js";
export { policyInitialEnvironment, POLICY_ENVIRONMENT_ROUTES } from "./bash/policy-environment.js";
export type { GhPrCreatePolicy } from "./bash/policies/gh-pr-create.js";
export * from "./audit.js";
export * from "./judge.js";
export * from "./config.js";
export * from "./policy/types.js";
export * from "./policy/evaluate.js";
export * from "./policy/config.js";
export * from "./policy/load.js";
export * from "./policy/events.js";
export * from "./policy/filesystem.js";
export * from "./policy/executable.js";
export * from "./policy/runtime.js";
export * from "./policy/trace.js";
