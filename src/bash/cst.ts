/** A half-open source range in the original Bash program. */
export interface SourceSpan {
  readonly start: number;
  readonly end: number;
}

export interface BashProgram {
  readonly kind: "program";
  readonly source: string;
  readonly statements: readonly BashStatement[];
}

export interface BashParseFailure {
  readonly kind: "parse-failure";
  readonly reason: string;
  readonly span: SourceSpan;
}

export type BashStatement =
  | BashCommand
  | BashFunction
  | BashList
  | BashPipeline
  | BashSubshell
  | BashGroup
  | BashIf
  | BashUnsupported;

export interface BashCommand {
  readonly kind: "command";
  readonly assignments: readonly BashAssignment[];
  readonly words: readonly BashWord[];
  readonly redirects: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashAssignment {
  readonly name: string;
  readonly value: BashWord | null;
  readonly span: SourceSpan;
}

export type BashWord =
  | BashLiteralWord
  | BashExpansionWord
  | BashCommandSubstitutionWord
  | BashConcatenationWord
  | BashUnsupportedWord;

export interface BashLiteralWord {
  readonly kind: "word";
  readonly text: string;
  readonly span: SourceSpan;
}

export interface BashExpansionWord {
  readonly kind: "expansion";
  readonly text: string;
  readonly statements: readonly BashStatement[];
  readonly span: SourceSpan;
}

export interface BashCommandSubstitutionWord {
  readonly kind: "command-substitution";
  readonly text: string;
  readonly statements: readonly BashStatement[];
  readonly span: SourceSpan;
}

export interface BashConcatenationWord {
  readonly kind: "concatenation";
  readonly text: string;
  readonly parts: readonly BashWord[];
  readonly span: SourceSpan;
}

export interface BashUnsupportedWord {
  readonly kind: "unsupported-word";
  readonly text: string;
  readonly reason: string;
  readonly statements: readonly BashStatement[];
  readonly span: SourceSpan;
}

export type BashRedirectKind = "input" | "output" | "append" | "unsupported";

export interface BashRedirect {
  readonly kind: BashRedirectKind;
  readonly target: BashWord | null;
  /** All projected destination words, in original source order. */
  readonly words: readonly BashWord[];
  readonly span: SourceSpan;
}

export interface BashFunction {
  readonly kind: "function";
  readonly name: string;
  readonly body: BashStatement;
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashList {
  readonly kind: "list";
  readonly statements: readonly BashStatement[];
  readonly operators: readonly ("&&" | "||")[];
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashPipeline {
  readonly kind: "pipeline";
  readonly statements: readonly BashStatement[];
  readonly negated: boolean;
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashSubshell {
  readonly kind: "subshell";
  readonly statements: readonly BashStatement[];
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashGroup {
  readonly kind: "group";
  readonly statements: readonly BashStatement[];
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashIf {
  readonly kind: "if";
  readonly condition: readonly BashStatement[];
  readonly consequent: readonly BashStatement[];
  readonly alternate: readonly BashStatement[];
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}

export interface BashUnsupported {
  readonly kind: "unsupported";
  readonly reason: string;
  /** Reachable supported statements retained beneath unsupported syntax. */
  readonly statements: readonly BashStatement[];
  readonly redirects?: readonly BashRedirect[];
  readonly span: SourceSpan;
}
