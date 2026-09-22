import { SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../../patterns.js";
import { basename, matchesAnyGlob } from "../../shell.js";
export { readOnlyAllow, readOnlyDefer, type ReadOnlyInvocationDecision, type ReadOnlyPolicyName } from "./read-only-decision.js";
export { HELM_CREDENTIAL_SAFE_COMMANDS, STRICT_ALLOWED_FLAGS, STRICT_READ_ONLY_COMMANDS } from "./read-only-data.js";

export interface AllowedFlag { readonly long?: string; readonly short?: string; readonly takesValue: boolean }

export function isSecretPath(value: string): boolean {
  const name = basename(value);
  return !!name && !matchesAnyGlob(name, SECRET_EXCEPTIONS) && matchesAnyGlob(name, SECRET_PATTERNS);
}
