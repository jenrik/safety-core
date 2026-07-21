// LLM-as-Judge verdict storage for the safety hook.
//
// Harness adapters store a verdict per tool call in the `tool_call` /
// `PreToolUse` event handler, and the TUI reads it back in `renderCall`.
// Verdicts are TUI-agnostic — only the harness adapter knows how to
// format them for display.

export interface JudgeVerdict {
  /** true = safe, false = suspicious (warning annotation). */
  safe: boolean;
  /** Human-readable reasoning for display. Keep short (one line). */
  reasoning: string;
}

const verdicts = new Map<string, JudgeVerdict>();

/** Store a verdict for the given tool call. */
export function setJudgeVerdict(toolCallId: string, verdict: JudgeVerdict): void {
  verdicts.set(toolCallId, verdict);
}

/** Retrieve the verdict for the given tool call, or undefined. */
export function getJudgeVerdict(toolCallId: string): JudgeVerdict | undefined {
  return verdicts.get(toolCallId);
}

/** Remove the verdict for the given tool call (cleanup). */
export function clearJudgeVerdict(toolCallId: string): void {
  verdicts.delete(toolCallId);
}
