import { SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../../patterns.js";
import { basename, matchesAnyGlob } from "../../shell.js";

export { STRICT_ALLOWED_FLAGS, STRICT_READ_ONLY_COMMANDS } from "./read-only-data.js";
export {
  type ReadOnlyInvocationDecision,
  type ReadOnlyPolicyName,
  readOnlyAllow,
  readOnlyDefer,
} from "./read-only-decision.js";

export interface AllowedFlag {
  readonly long?: string;
  readonly short?: string;
  readonly takesValue: boolean;
}

export function isSecretPath(value: string): boolean {
  const name = basename(value);
  return !!name && !matchesAnyGlob(name, SECRET_EXCEPTIONS) && matchesAnyGlob(name, SECRET_PATTERNS);
}
