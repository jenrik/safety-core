import type { NormalizedRedirect, ResolvedWord } from "./expand.js";

/** Descriptor destinations are facts, never captured process/file contents. */
export type BashDescriptorSource =
  | { readonly kind: "inherited"; readonly descriptor: number }
  | {
      readonly kind: "file";
      readonly path: ResolvedWord | null;
      readonly cwd: string | null;
      readonly mode: "input" | "output" | "append" | "read-write";
    }
  | { readonly kind: "here-string"; readonly content: ResolvedWord | null }
  | { readonly kind: "pipeline" | "process-substitution" | "closed" | "unknown" };

export type BashIoContext = Readonly<Record<string, BashDescriptorSource>>;

export function inheritedBashIo(): BashIoContext {
  return Object.freeze(
    Object.fromEntries([0, 1, 2].map((descriptor) => [descriptor, Object.freeze({ kind: "inherited", descriptor })])),
  );
}

/** Apply operations left to right: duplication snapshots the current binding. */
export function redirectBashIo(
  inherited: BashIoContext,
  redirects: readonly NormalizedRedirect[],
  cwd: string | null,
): BashIoContext {
  const result: Record<string, BashDescriptorSource> = { ...inherited };
  for (const redirect of redirects) {
    const descriptor =
      redirect.descriptor === undefined
        ? redirect.kind === "input" ||
          redirect.kind === "here-string" ||
          redirect.kind === "here-document" ||
          redirect.kind === "read-write"
          ? 0
          : 1
        : redirect.descriptor;
    if (descriptor === null) {
      for (const key of Object.keys(result)) result[key] = Object.freeze({ kind: "unknown" });
      continue;
    }
    let source: BashDescriptorSource;
    if (redirect.kind === "duplicate") {
      const target = redirect.target;
      if (target?.kind === "known" && /^\d+$/.test(target.value) && Number.isSafeInteger(Number(target.value))) {
        const from = Number(target.value);
        source = result[from] ?? Object.freeze({ kind: "inherited", descriptor: from });
      } else source = Object.freeze({ kind: "unknown" });
    } else if (redirect.kind === "close") source = Object.freeze({ kind: "closed" });
    else if (redirect.kind === "here-string")
      source = Object.freeze({ kind: "here-string", content: redirect.content ?? null });
    else if (["input", "output", "append", "read-write"].includes(redirect.kind)) {
      source =
        redirect.target?.kind === "unknown" && redirect.target.reason.kind === "process-substitution"
          ? Object.freeze({ kind: "process-substitution" })
          : Object.freeze({
              kind: "file",
              path: redirect.target,
              cwd,
              mode: redirect.kind as "input" | "output" | "append" | "read-write",
            });
    } else source = Object.freeze({ kind: "unknown" });
    result[descriptor] = source;
    if (redirect.operator === "&>" || redirect.operator === "&>>") result[2] = source;
  }
  return Object.freeze(result);
}
