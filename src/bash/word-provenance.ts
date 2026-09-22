/** Runtime-only provenance for known words materialized from bindings. */
const bindingResolvedWords = new WeakSet<object>();

export function isBindingResolvedWord(word: { readonly kind: string }): boolean {
  return word.kind === "known" && bindingResolvedWords.has(word);
}

export function markBindingResolvedWord<T extends object>(word: T): T {
  bindingResolvedWords.add(word);
  return word;
}
